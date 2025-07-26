const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const nodemailer = require('nodemailer');
const config = require('./config');
require('dotenv').config();
const ApprovalRequest = require('./models/ApprovalRequest');

// Check if email credentials are set
const emailUser = process.env.EMAIL_USER || config.email?.user;
const emailPass = process.env.EMAIL_PASS || config.email?.pass;

if (!emailUser || !emailPass) {
    console.error('Email credentials not found in environment variables or config');
    console.log('Please create a .env file with EMAIL_USER and EMAIL_PASS or set them in config.js');
}

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: emailUser,
        pass: emailPass
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Verify email configuration
transporter.verify(function(error, success) {
    if (error) {
        console.error('Email configuration error:', error);
        console.log('Please check your config.js file and ensure email credentials are set correctly');
    } else {
        console.log('Email server is ready to send messages');
    }
});

// Function to generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Store OTPs temporarily (in production, use Redis or similar)
const otpStore = new Map();

const app = express();
const PORT = 3000;

// Middlewares
app.use(cors({
    origin: 'http://localhost:3000', // Specify your frontend origin
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 10 * 60 * 1000, // 10 minutes
        sameSite: 'lax'
    },
    rolling: true // Reset expiration on each request
}));

// Debug middleware for session tracking
app.use((req, res, next) => {
    console.log('Session Debug:', {
        sessionID: req.sessionID,
        hasSession: !!req.session,
        user: req.session?.user,
        cookies: req.cookies,
        url: req.url
    });
    next();
});

// Add middleware to check session
app.use((req, res, next) => {
    // Debug session state
    console.log('Session state:', {
        hasSession: !!req.session,
        sessionID: req.sessionID,
        user: req.session?.user
    });
    
    // Initialize session if needed
    if (!req.session) {
        req.session = {};
    }
    
    next();
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/signupDB')
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Mongoose Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'faculty' },
    facultyId: String
});

const extraDetailsSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    fullName: String,
    dob: String,
    facultyId: String,
    address: String,
    campus: String,
    campusName: String,
    email: String,
    phone: String,
    altPhone: String,
    bankAccount: String,
    ifsc: String,
    micr: String,
    branchName: String,
    branchAddress: String,
    qualification: String,
    expertise: String,
    assignedSubject: { type: String, default: "" },
    isAssigned: { type: Boolean, default: false }
});

const facultyAssignmentSchema = new mongoose.Schema({
    facultyId: String,
    facultyName: String,
    subjectCode: String,
    subjectName: String,
    regulation: String,
    role: String,
    isAssigned: Boolean,
    response: String,
    createdAt: { type: Date, default: Date.now },
    assignedBy: String,
    year: Number,
    questionPaperStatus: { type: String, enum: ['pending', 'submitted', 'approved', 'rejected'], default: 'pending' },
    deadlineDate: { type: Date }
});


const questionPaperSchema = new mongoose.Schema({
    facultyId: { type: String, required: true },
    examName: { type: String, required: true },
    department: { type: String, required: true },
    semester: { type: String, required: true },
    subjectCode: { type: String, required: true },
    subjectTitle: { type: String, required: true },
    regulation: { type: String, required: true },
    year: { type: Number, required: true },
    examDate: { type: Date, required: true },
    session: { type: String, required: true },
    time: { type: String, required: true },
    maxMarks: { type: String, required: true },
    partAQuestions: { type: [String], required: true },
    partBQuestions: { type: [String], required: true },
    partCQuestions: { type: [String], required: true },
    createdAt: { type: Date, default: Date.now },
    scrutinyStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    scrutinyRemarks: { type: String, default: '' },
    scrutinizerId: { type: String, default: '' },
    scrutinizerName: { type: String, default: '' },
    scrutinyRequestStatus: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    submissionDeadline: { type: Date },
    scrutinyDeadline: { type: Date },
    submissionNotificationSent: { type: Boolean, default: false },
    scrutinyNotificationSent: { type: Boolean, default: false },
    adminApproval: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    adminApprovalDate: { type: Date }
});

// Models
const User = mongoose.model('User', userSchema);
const ExtraDetails = mongoose.model('ExtraDetails', extraDetailsSchema);
const FacultyAssignment = mongoose.model('FacultyAssignment', facultyAssignmentSchema);
const QuestionPaper = mongoose.model('QuestionPaper', questionPaperSchema);

app.post('/save-faculty-assignment', async (req, res) => {
    try {
        const { facultyId, facultyName, subjectCode, subjectName, regulation, role, deadlineDate } = req.body;
        
        console.log('Received save request:', req.body);

        if (!facultyId || !facultyName || !subjectCode || !subjectName || !regulation || !role || !deadlineDate) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Check if faculty exists in ExtraDetails
        const extraDetails = await ExtraDetails.findOne({ facultyId });
        if (!extraDetails) {
            return res.status(404).json({ message: 'Faculty not found. Please check the Faculty ID.' });
        }

        // Check if faculty name matches
        if (extraDetails.fullName !== facultyName) {
            return res.status(400).json({ message: 'Faculty ID and Faculty Name do not match.' });
        }

        // Check for duplicate assignment
        const existingAssignment = await FacultyAssignment.findOne({ 
            facultyId, 
            subjectCode, 
            role 
        });
        
        if (existingAssignment) {
            return res.status(400).json({ message: 'This subject is already assigned to this faculty' });
        }

        // Create and save the new faculty assignment
        const newFacultyAssignment = new FacultyAssignment({
            facultyId,
            facultyName,
            subjectCode,
            subjectName,
            regulation,
            role,
            isAssigned: false,
            response: '',
            year: new Date().getFullYear(),
            assignedBy: req.session.user?.username || "ADMIN",
            deadlineDate: new Date(deadlineDate)
        });

        await newFacultyAssignment.save();
        console.log('Saved new faculty assignment:', newFacultyAssignment);

        res.status(201).json({ 
            message: 'Faculty Assignment saved successfully',
            assignment: newFacultyAssignment
        });
    } catch (err) {
        console.error('Error saving faculty assignment:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.get('/api/faculty-assignments', async (req, res) => {
    try {
        // Get assignments from FacultyAssignment collection
        const facultyAssignments = await FacultyAssignment.find({})
            .sort({ createdAt: -1 });

        // Create a map to track unique assignments by facultyId and subjectCode
        const uniqueAssignments = new Map();

        // Process faculty assignments first (these take precedence)
        facultyAssignments.forEach(assignment => {
            const key = `${assignment.facultyId}-${assignment.subjectCode}-${assignment.role}`;
            uniqueAssignments.set(key, {
                facultyId: assignment.facultyId,
                facultyName: assignment.facultyName,
                subjectCode: assignment.subjectCode,
                subjectName: assignment.subjectName,
                regulation: assignment.regulation,
                role: assignment.role,
                response: assignment.response || '',
                isAssigned: assignment.isAssigned,
                createdAt: assignment.createdAt,
                questionPaperStatus: assignment.questionPaperStatus,
                deadlineDate: assignment.deadlineDate
            });
        });

        // Convert map values to array
        const assignments = Array.from(uniqueAssignments.values());

        // Sort by creation date (newest first)
        assignments.sort((a, b) => {
            if (a.createdAt && b.createdAt) {
                return new Date(b.createdAt) - new Date(a.createdAt);
            }
            return 0;
        });

        res.json(assignments);
    } catch (error) {
        console.error("Error fetching faculty assignments:", error);
        res.status(500).json({ message: "Error fetching assignments" });
    }
});

app.get('/get-faculty-assignment-status', async (req, res) => {
    try {
        console.log('Session check in get-faculty-assignment-status:', req.session);
        
        if (!req.session || !req.session.user) {
            console.log('No session or user found');
            return res.status(401).json({ message: "Please log in again" });
        }

        const facultyId = req.session.user.facultyId;
        if (!facultyId) {
            console.log('No faculty ID in session:', req.session.user);
            return res.status(400).json({ message: "Faculty ID not found in session" });
        }

        console.log('Fetching assignments for facultyId:', facultyId);

        // First check for any unresponded assignments
        const unrespondedAssignment = await FacultyAssignment.findOne({ 
            facultyId, 
            response: '' 
        });

        if (unrespondedAssignment) {
            console.log('Found unresponded assignment:', unrespondedAssignment);
            return res.json({
                prompt: true,
                data: {
                    subjectCode: unrespondedAssignment.subjectCode,
                    subjectName: unrespondedAssignment.subjectName,
                    regulation: unrespondedAssignment.regulation,
                    role: unrespondedAssignment.role,
                    response: unrespondedAssignment.response,
                    isAssigned: unrespondedAssignment.isAssigned,
                    questionPaperStatus: unrespondedAssignment.questionPaperStatus
                }
            });
        }

        // If no unresponded assignments, return all assignments
        const assignments = await FacultyAssignment.find({ facultyId })
            .sort({ createdAt: -1 });

        console.log('Found assignments:', assignments);

        const formattedAssignments = assignments.map(assignment => ({
            subjectCode: assignment.subjectCode,
            subjectName: assignment.subjectName,
            regulation: assignment.regulation,
            role: assignment.role,
            response: assignment.response || '',
            isAssigned: assignment.isAssigned,
            questionPaperStatus: assignment.questionPaperStatus
        }));

        res.json(formattedAssignments);
    } catch (error) {
        console.error("Error fetching faculty assignments:", error);
        res.status(500).json({ message: "Error fetching assignments: " + error.message });
    }
});

app.post('/update-faculty-assignment', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const { response, subjectCode, role } = req.body;
        const facultyId = req.session.user.facultyId;

        if (!facultyId || !subjectCode || !role) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // Find the assignment
        const assignment = await FacultyAssignment.findOne({
            facultyId,
            subjectCode,
            role
        });

        if (!assignment) {
            return res.status(404).json({ message: "Assignment not found" });
        }

        // Check if assignment already has a response
        if (assignment.response && assignment.response !== '') {
            return res.status(400).json({ message: "Assignment already responded to" });
        }

        // Update the assignment
        assignment.response = response;
        assignment.isAssigned = response === 'yes';
        assignment.respondedAt = new Date();
        
        await assignment.save();

        // Update ExtraDetails
        await ExtraDetails.updateOne(
            { facultyId },
            { 
                $set: { 
                    isAssigned: response === 'yes',
                    assignedSubject: response === 'yes' ? assignment.subjectName : ''
                }
            }
        );

        res.json({ 
            message: "Assignment updated successfully",
            assignment: {
                subjectCode: assignment.subjectCode,
                subjectName: assignment.subjectName,
                regulation: assignment.regulation,
                role: assignment.role,
                response: assignment.response,
                isAssigned: assignment.isAssigned
            }
        });
    } catch (error) {
        console.error("Error updating assignment:", error);
        res.status(500).json({ message: "Error updating assignment" });
    }
});

app.post('/remove-faculty-assignment', async (req, res) => {
    const { facultyId, subjectCode, role } = req.body;

    if (!facultyId || !subjectCode) {
        console.log('Missing required fields:', { facultyId, subjectCode });
        return res.status(400).json({ message: 'Faculty ID and Subject Code are required' });
    }

    try {
        // Remove the specific assignment from FacultyAssignment collection
        const result = await FacultyAssignment.deleteOne({ facultyId, subjectCode, role });
        console.log(`Deleted faculty assignment:`, { facultyId, subjectCode, role, deletedCount: result.deletedCount });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'No assignment found for the faculty' });
        }

        // Find and remove any question papers associated with this faculty and subject
        const questionPapers = await QuestionPaper.find({ facultyId, subjectCode });
        console.log(`Found ${questionPapers.length} question papers to process`);
        
        // For each question paper, we need to handle scrutiny assignments
        let scrutinyAssignmentsRemoved = 0;
        for (const paper of questionPapers) {
            if (paper.scrutinizerId) {
                // Remove the scrutiny assignment from FacultyAssignment
                const scrutinyResult = await FacultyAssignment.deleteOne({ 
                    facultyId: paper.scrutinizerId, 
                    subjectCode, 
                    role: 'Scrutinizer' 
                });
                if (scrutinyResult.deletedCount > 0) {
                    scrutinyAssignmentsRemoved++;
                }
            }
        }
        console.log(`Removed ${scrutinyAssignmentsRemoved} scrutiny assignments`);

        // Now delete the question papers
        const questionPaperResult = await QuestionPaper.deleteMany({ facultyId, subjectCode });
        console.log(`Deleted ${questionPaperResult.deletedCount} question papers`);

        res.status(200).json({ 
            message: 'Faculty assignment and associated question papers removed successfully',
            deletedCount: result.deletedCount,
            questionPapersDeleted: questionPaperResult.deletedCount,
            scrutinyAssignmentsRemoved
        });
    } catch (err) {
        console.error('Error deleting faculty assignment:', err);
        res.status(500).json({ 
            message: 'Server error while deleting',
            error: err.message 
        });
    }
});

app.post("/signup", async (req, res) => {
    const { username, password, role = 'faculty' } = req.body;
    const facultyId = req.body.facultyId || Math.floor(1000 + Math.random() * 9000).toString(); // Generate unique facultyId

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required." });
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists." });
        }

        const newUser = new User({ username, password, role: role.toLowerCase(), facultyId });
        await newUser.save();
        req.session.user = newUser;

        res.status(201).json({ message: "Signup successful!" });
    } catch (error) {
        console.error("Signup error:", error);
        if (error.code === 11000) {
            res.status(400).json({ message: "Duplicate facultyId. Please try again." });
        } else {
            res.status(500).json({ message: "Error signing up." });
        }
    }
});

//  Save Extra Faculty Details (Missing Route Added)
app.post('/signup-details', async (req, res) => {
    const {
        username, fullName, dob, facultyId, address, campus, campusName,
        email, phone, altPhone, bankAccount, ifsc, micr,
        branchName, branchAddress, qualification, expertise
    } = req.body;

    try {
        const existing = await ExtraDetails.findOne({ username });
        if (existing) {
            return res.status(400).json({ message: "Details already submitted." });
        }

        await User.updateOne({ username }, { $set: { facultyId } })

        const extraDetails = new ExtraDetails({
            username, fullName, dob, facultyId, address, campus, campusName,
            email, phone, altPhone, bankAccount, ifsc, micr,
            branchName, branchAddress, qualification, expertise
        });

        await extraDetails.save();
        res.status(201).json({ message: "Extra details saved successfully!" });
    } catch (err) {
        console.error("Signup-details error:", err);
        res.status(500).json({ message: "Failed to save details." });
    }
});

// Full Profile API
app.get('/full-profile', async (req, res) => {
    const { username } = req.query;

    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const extraDetails = await ExtraDetails.findOne({ username });
    if (!extraDetails) {
        return res.status(400).json({ message: 'Extra details not found' });
    }

    res.status(200).json({ user, extraDetails });
});

// Admin Login
app.post('/admin_login', (req, res) => {
    const { username, password } = req.body;

    if (username === 'ADMIN' && password === 'admin@CEG') {
        req.session.user = { username: 'ADMIN', role: 'admin' };
        res.status(200).json({ message: 'Admin login successful' });
    } else {
        res.status(401).json({ message: 'Invalid admin credentials' });
    }
});

// Faculty Login
app.post('/faculty_login', async (req, res) => {
    const { username, password } = req.body;

    try {
        console.log('Login attempt for:', username);

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required." });
        }

        // Check for the user with matching username and password
        const user = await User.findOne({ username, password, role: 'faculty' });

        if (!user) {
            console.log('Invalid credentials for:', username);
            return res.status(401).json({ message: "Invalid username or password" });
        }

        // Get the faculty details
        const extraDetails = await ExtraDetails.findOne({ username });
        
        // Create session data
        const userData = {
            username: user.username,
            role: user.role,
            facultyId: user.facultyId || (extraDetails ? extraDetails.facultyId : null)
        };

        // Set session
        req.session.user = userData;

        // Save session and wait for it to complete
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    reject(err);
                } else {
                    console.log('Session saved successfully:', {
                        sessionID: req.sessionID,
                        userData: userData
                    });
                    resolve();
                }
            });
        });

        // Send success response with user data
        res.status(200).json({
            message: "Login successful!",
            user: userData
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});

// Add a debug endpoint to check session
app.get('/check-session', (req, res) => {
    if (req.session && req.session.user) {
        res.json({ user: req.session.user });
    } else {
        res.status(401).json({ message: "No active session" });
    }
});

// Admin Dashboard
app.get('/dashboard.html', (req, res) => {
    // Allow access if user is admin or if no user is logged in
    if (!req.session.user || req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'public/admin_dashboard.html'));
    } else {
        res.redirect('/');
    }
});

// Faculty Dashboard
app.get('/faculty_dashboard.html', (req, res) => {
    // Allow access if user is faculty or if no user is logged in
    if (!req.session.user || req.session.user.role === 'faculty') {
        res.sendFile(path.join(__dirname, 'public/faculty_dashboard.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/get-question-assigner-status', async (req, res) => {
    const { facultyId } = req.session.user;
    try {
        const assignment = await FacultyAssignment.findOne({ facultyId, response: '' });
        if (assignment) {
            return res.status(200).json({ 
                prompt: true, 
                data: assignment 
            });
        }
        res.status(200).json({ prompt: false });
    } catch (err) {
        res.status(500).json({ message: 'Error checking status' });
    }
});

app.get('/question-assigner-responses', async (req, res) => {
    try {
        const responses = await FacultyAssignment.find({});
        res.status(200).json(responses);
    } catch (err) {
        res.status(500).json({ message: "Error fetching responses." });
    }
});

// Endpoint to check if a faculty member has access to set_question_paper.html
app.get('/check-assignment-access', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const facultyId = req.session.user.facultyId;
        const assignment = await FacultyAssignment.findOne({ facultyId, response: 'yes' });

        if (assignment) {
            return res.status(200).json({ accessGranted: true });
        } else {
            return res.status(403).json({ accessGranted: false });
        }
    } catch (error) {
        console.error('Error checking assignment access:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout endpoint
app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).json({ message: "Error during logout" });
        }
        res.json({ message: "Logged out successfully" });
    });
});

app.post('/api/questionpaper', async (req, res) => {
    try {
        const {
            facultyId,
            examName,
            department,
            semester,
            subjectCode,
            subjectTitle,
            regulation,
            examDate,
            time,
            maxMarks,
            partAQuestions,
            partBQuestions,
            partCQuestions,
            role,
            session
        } = req.body;

        // Validate required fields
        if (!facultyId || !examName || !department || !semester || !subjectCode || !subjectTitle || !regulation || !examDate || !time || !maxMarks || !partAQuestions || !partBQuestions || !partCQuestions || !role || !session) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // Get the corresponding assignment to get the deadline
        const assignment = await FacultyAssignment.findOne({
            facultyId,
            subjectCode,
            role: { $regex: new RegExp(`^${role}$`, 'i') }
        });

        if (!assignment) {
            return res.status(404).json({ message: 'No assignment found for this subject and role.' });
        }

        // Ensure deadlineDate is a valid Date object
        const deadlineDate = new Date(assignment.deadlineDate);
        if (isNaN(deadlineDate.getTime())) {
            console.error('Invalid deadline date:', assignment.deadlineDate);
            return res.status(400).json({ message: 'Invalid deadline date in assignment.' });
        }

        // Calculate year from semester
        let year = 1;
        const semMatch = (semester || '').match(/(\d+)/);
        if (semMatch) {
            const semNum = parseInt(semMatch[1], 10);
            if (semNum >= 1 && semNum <= 2) year = 1;
            else if (semNum >= 3 && semNum <= 4) year = 2;
            else if (semNum >= 5 && semNum <= 6) year = 3;
            else if (semNum >= 7 && semNum <= 8) year = 4;
        }

        // Create a new question paper document
        const newQuestionPaper = new QuestionPaper({
            facultyId,
            examName,
            department,
            semester,
            subjectCode,
            subjectTitle,
            regulation,
            year,
            examDate: new Date(examDate),
            time,
            maxMarks,
            partAQuestions,
            partBQuestions,
            partCQuestions,
            role,
            session,
            submissionDeadline: deadlineDate
        });

        // Save the question paper to the database
        await newQuestionPaper.save();

        // Debug: print the update query
        console.log('Updating FacultyAssignment:', { facultyId, subjectCode, role });

        // Normalize the role value
        const normalizedRole = (role || '').trim();
        // Log all assignments for this faculty and subject before update
        const assignmentsBefore = await FacultyAssignment.find({ facultyId, subjectCode });
        console.log('Assignments before update:', assignmentsBefore);

        // Update the faculty assignment status with case-insensitive role match (debug: no response condition)
        const updateResult = await FacultyAssignment.updateMany(
            { facultyId, subjectCode, role: { $regex: new RegExp(`^${normalizedRole}$`, 'i') } },
            { $set: { questionPaperStatus: 'submitted' } }
        );

        console.log('Update result:', updateResult);
        // Log all assignments for this faculty and subject after update
        const assignments = await FacultyAssignment.find({ facultyId, subjectCode });
        console.log('Assignments after update:', assignments);

        res.status(201).json({ message: 'Question paper saved successfully!' });
    } catch (error) {
        console.error('Error saving question paper:', error);
        res.status(500).json({ message: 'Server error while saving question paper.' });
    }
});

app.get('/api/questionpapers', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const questionPapers = await QuestionPaper.find({}).sort({ createdAt: -1 });
        res.json(questionPapers);
    } catch (error) {
        console.error('Error fetching question papers:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/questionpaper/:id', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const questionPaper = await QuestionPaper.findById(req.params.id);
        if (!questionPaper) {
            return res.status(404).json({ message: 'Question paper not found' });
        }

        // Allow access if user is admin or if they are the faculty who submitted the paper or the scrutinizer
        if (req.session.user.role !== 'admin' && 
            req.session.user.facultyId !== questionPaper.facultyId && 
            req.session.user.facultyId !== questionPaper.scrutinizerId) {
            return res.status(403).json({ message: 'Access denied' });
        }

        // Format the response
        const formattedPaper = {
            _id: questionPaper._id,
            subjectCode: questionPaper.subjectCode,
            subjectTitle: questionPaper.subjectTitle,
            department: questionPaper.department,
            semester: questionPaper.semester,
            regulation: questionPaper.regulation,
            time: questionPaper.time,
            maxMarks: questionPaper.maxMarks,
            partAQuestions: questionPaper.partAQuestions,
            partBQuestions: questionPaper.partBQuestions,
            partCQuestions: questionPaper.partCQuestions,
            scrutinyStatus: questionPaper.scrutinyStatus,
            scrutinyRequestStatus: questionPaper.scrutinyRequestStatus,
            scrutinyRemarks: questionPaper.scrutinyRemarks,
            scrutinizerId: questionPaper.scrutinizerId,
            scrutinizerName: questionPaper.scrutinizerName,
            examDate: questionPaper.examDate
        };

        res.json(formattedPaper);
    } catch (error) {
        console.error('Error fetching question paper:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/questionpaper/:id/download', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const questionPaper = await QuestionPaper.findById(req.params.id);
        if (!questionPaper) {
            return res.status(404).json({ message: 'Question paper not found' });
        }

        // Allow access if user is admin or if they are the faculty who submitted the paper or the scrutinizer
        if (req.session.user.role !== 'admin' && 
            req.session.user.facultyId !== questionPaper.facultyId && 
            req.session.user.facultyId !== questionPaper.scrutinizerId) {
            return res.status(403).json({ message: 'Access denied' });
        }

        // Generate HTML content with proper formatting
        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Question Paper - ${questionPaper.subjectCode}</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        margin: 20px;
                        line-height: 1.6;
                    }
                    .header { 
                        text-align: center; 
                        margin-bottom: 20px;
                        border-bottom: 2px solid #333;
                        padding-bottom: 20px;
                    }
                    .section { 
                        margin-bottom: 20px;
                        page-break-inside: avoid;
                    }
                    .question { 
                        margin-bottom: 10px;
                        padding-left: 20px;
                    }
                    .part-title {
                        font-weight: bold;
                        margin-bottom: 10px;
                        color: #333;
                    }
                    @media print {
                        body {
                            margin: 0;
                            padding: 20px;
                        }
                        .header {
                            border-bottom: 2px solid #000;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>${questionPaper.examName}</h1>
                    <p><strong>Department:</strong> ${questionPaper.department}</p>
                    <p><strong>Semester:</strong> ${questionPaper.semester}</p>
                    <p><strong>Subject Code:</strong> ${questionPaper.subjectCode}</p>
                    <p><strong>Subject Title:</strong> ${questionPaper.subjectTitle}</p>
                    <p><strong>Regulation:</strong> ${questionPaper.regulation}</p>
                    <p><strong>Time:</strong> ${questionPaper.time}</p>
                    <p><strong>Maximum Marks:</strong> ${questionPaper.maxMarks}</p>
                </div>

                <div class="section">
                    <div class="part-title">Part A (10 x 2 = 20 Marks)</div>
                    ${questionPaper.partAQuestions.map((q, i) => `
                        <div class="question">${i + 1}. ${q}</div>
                    `).join('')}
                </div>

                <div class="section">
                    <div class="part-title">Part B (8 x 8 = 64 Marks)</div>
                    ${questionPaper.partBQuestions.map((q, i) => `
                        <div class="question">${i + 11}. ${q}</div>
                    `).join('')}
                </div>

                <div class="section">
                    <div class="part-title">Part C (2 x 8 = 16 Marks)</div>
                    ${questionPaper.partCQuestions.map((q, i) => `
                        <div class="question">${i + 23}. ${q}</div>
                    `).join('')}
                </div>
            </body>
            </html>
        `;

        // Set headers for file download
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename=question_paper_${questionPaper.subjectCode}.html`);
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        
        // Send the content
        res.send(htmlContent);
    } catch (error) {
        console.error('Error downloading question paper:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/assign-scrutinizer', async (req, res) => {
    try {
        const { questionPaperId, scrutinizerId, scrutinizerName, scrutinyDeadline } = req.body;
        
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const questionPaper = await QuestionPaper.findById(questionPaperId);
        if (!questionPaper) {
            return res.status(404).json({ error: 'Question paper not found' });
        }

        questionPaper.scrutinizerId = scrutinizerId;
        questionPaper.scrutinizerName = scrutinizerName;
        questionPaper.scrutinyRequestStatus = 'pending';
        questionPaper.scrutinyDeadline = scrutinyDeadline;
        questionPaper.scrutinyNotificationSent = false;

        await questionPaper.save();
        res.json({ message: 'Scrutinizer assigned successfully' });
    } catch (error) {
        console.error('Error assigning scrutinizer:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/submit-scrutiny', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const { questionPaperId, remarks, status } = req.body;

        if (!questionPaperId || !remarks || !status) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const questionPaper = await QuestionPaper.findById(questionPaperId);
        if (!questionPaper) {
            return res.status(404).json({ message: 'Question paper not found' });
        }

        if (questionPaper.scrutinizerId !== req.session.user.facultyId) {
            return res.status(403).json({ message: 'You are not assigned as scrutinizer for this paper' });
        }

        if (questionPaper.scrutinyStatus !== 'pending') {
            return res.status(400).json({ message: 'Question paper has already been scrutinized' });
        }

        questionPaper.scrutinyStatus = status;
        questionPaper.scrutinyRemarks = remarks;
        await questionPaper.save();

        res.json({ message: 'Scrutiny submitted successfully' });
    } catch (error) {
        console.error('Error submitting scrutiny:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/scrutiny-papers', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const scrutinizerId = req.session.user.facultyId;
        const questionPapers = await QuestionPaper.find({
            scrutinizerId,
            scrutinyRequestStatus: 'accepted',
            scrutinyStatus: 'pending'
        }).sort({ createdAt: -1 });

        // Format the response
        const formattedPapers = questionPapers.map(paper => ({
            _id: paper._id,
            subjectCode: paper.subjectCode,
            subjectTitle: paper.subjectTitle,
            department: paper.department,
            semester: paper.semester,
            regulation: paper.regulation,
            time: paper.time,
            maxMarks: paper.maxMarks,
            scrutinyStatus: paper.scrutinyStatus,
            scrutinyRequestStatus: paper.scrutinyRequestStatus,
            scrutinyRemarks: paper.scrutinyRemarks,
            scrutinizerId: paper.scrutinizerId,
            scrutinizerName: paper.scrutinizerName
        }));

        res.json(formattedPapers);
    } catch (error) {
        console.error('Error fetching scrutiny papers:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update the pending scrutiny requests endpoint
app.get('/api/pending-scrutiny-requests', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const scrutinizerId = req.session.user.facultyId;
        const questionPapers = await QuestionPaper.find({
            scrutinizerId,
            scrutinyRequestStatus: 'pending'
        }).sort({ createdAt: -1 });

        // Format the response to include necessary details
        const formattedPapers = questionPapers.map(paper => ({
            _id: paper._id,
            subjectCode: paper.subjectCode,
            subjectTitle: paper.subjectTitle,
            department: paper.department,
            semester: paper.semester,
            regulation: paper.regulation,
            time: paper.time,
            maxMarks: paper.maxMarks,
            scrutinyStatus: paper.scrutinyStatus,
            scrutinyRequestStatus: paper.scrutinyRequestStatus
        }));

        res.json(formattedPapers);
    } catch (error) {
        console.error('Error fetching pending scrutiny requests:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add new endpoint for faculty to respond to scrutiny request
app.post('/api/respond-to-scrutiny-request', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const { questionPaperId, response } = req.body;

        if (!questionPaperId || !response) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const questionPaper = await QuestionPaper.findById(questionPaperId);
        if (!questionPaper) {
            return res.status(404).json({ message: 'Question paper not found' });
        }

        if (questionPaper.scrutinizerId !== req.session.user.facultyId) {
            return res.status(403).json({ message: 'You are not assigned as scrutinizer for this paper' });
        }

        questionPaper.scrutinyRequestStatus = response;
        await questionPaper.save();

        res.json({ message: 'Response recorded successfully' });
    } catch (error) {
        console.error('Error responding to scrutiny request:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add new endpoint to check deadlines
app.get('/api/check-deadlines', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const now = new Date();
        const threeDaysFromNow = new Date(now.getTime() + (3 * 24 * 60 * 60 * 1000));

        console.log('Checking deadlines for facultyId:', req.session.user.facultyId);
        console.log('Current time:', now);
        console.log('Three days from now:', threeDaysFromNow);

        // Find papers with approaching deadlines
        const papers = await QuestionPaper.find({
            $or: [
                {
                    facultyId: req.session.user.facultyId,
                    submissionDeadline: { $exists: true, $ne: null }
                },
                {
                    scrutinizerId: req.session.user.facultyId,
                    scrutinyDeadline: { $exists: true, $ne: null }
                }
            ]
        });

        console.log('Found papers with deadlines:', papers);

        // Find assignments with approaching deadlines
        const assignments = await FacultyAssignment.find({
            facultyId: req.session.user.facultyId,
            deadlineDate: { $exists: true, $ne: null },
            questionPaperStatus: 'pending'
        });

        console.log('Found assignments with deadlines:', assignments);

        // Format notifications for papers
        
        const paperNotifications = papers.map(paper => {
            const isSubmission = paper.facultyId === req.session.user.facultyId;
            const deadline = isSubmission ? paper.submissionDeadline : paper.scrutinyDeadline;
            
            console.log('Processing paper:', {
                paperId: paper._id,
                subjectCode: paper.subjectCode,
                deadline: deadline,
                isSubmission: isSubmission
            });

            // Ensure deadline is a valid Date object
            let deadlineDate;
            if (typeof deadline === 'string') {
                deadlineDate = new Date(deadline);
            } else if (deadline instanceof Date) {
                deadlineDate = deadline;
            } else {
                console.error('Invalid deadline type:', typeof deadline);
                return null;
            }

            if (isNaN(deadlineDate.getTime())) {
                console.error('Invalid deadline date:', deadline);
                return null;
            }

            // Only include if deadline is within the next 3 days
            if (deadlineDate > threeDaysFromNow || deadlineDate < now) {
                return null;
            }

            const timeDiff = deadlineDate.getTime() - now.getTime();
            const daysLeft = Math.max(0, Math.ceil(timeDiff / (1000 * 60 * 60 * 24)));

            console.log('Calculated days left:', {
                paperId: paper._id,
                deadlineDate: deadlineDate,
                timeDiff: timeDiff,
                daysLeft: daysLeft
            });

            return {
                paperId: paper._id,
                subjectCode: paper.subjectCode,
                subjectTitle: paper.subjectTitle,
                type: isSubmission ? 'submission' : 'scrutiny',
                deadline: deadlineDate,
                daysLeft: daysLeft,
                message: `Deadline for ${isSubmission ? 'submitting' : 'scrutinizing'} ${paper.subjectCode} - ${paper.subjectTitle} is in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`
            };
        }).filter(notification => notification !== null);

        // Format notifications for assignments
        const assignmentNotifications = assignments.map(assignment => {
            console.log('Processing assignment:', {
                assignmentId: assignment._id,
                subjectCode: assignment.subjectCode,
                deadlineDate: assignment.deadlineDate
            });

            // Ensure deadlineDate is a valid Date object
            let deadlineDate;
            if (typeof assignment.deadlineDate === 'string') {
                deadlineDate = new Date(assignment.deadlineDate);
            } else if (assignment.deadlineDate instanceof Date) {
                deadlineDate = assignment.deadlineDate;
            } else {
                console.error('Invalid deadline type:', typeof assignment.deadlineDate);
                return null;
            }

            if (isNaN(deadlineDate.getTime())) {
                console.error('Invalid deadline date:', assignment.deadlineDate);
                return null;
            }

            // Only include if deadline is within the next 3 days
            if (deadlineDate > threeDaysFromNow || deadlineDate < now) {
                return null;
            }

            const timeDiff = deadlineDate.getTime() - now.getTime();
            const daysLeft = Math.max(0, Math.ceil(timeDiff / (1000 * 60 * 60 * 24)));

            console.log('Calculated days left:', {
                assignmentId: assignment._id,
                deadlineDate: deadlineDate,
                timeDiff: timeDiff,
                daysLeft: daysLeft
            });

            return {
                assignmentId: assignment._id,
                subjectCode: assignment.subjectCode,
                subjectTitle: assignment.subjectName,
                type: 'assignment',
                deadline: deadlineDate,
                daysLeft: daysLeft,
                message: `Deadline for submitting question paper for ${assignment.subjectCode} - ${assignment.subjectName} is in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`
            };
        }).filter(notification => notification !== null);

        // Combine notifications
        const notifications = [...paperNotifications, ...assignmentNotifications];
        console.log('Generated notifications:', notifications);

        res.json({ notifications });
    } catch (error) {
        console.error('Error checking deadlines:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Forgot Password - Send OTP
app.post('/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ message: 'Username is required' });
        }

        // First find the user to get facultyId
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Then find faculty details using facultyId
        const extraDetails = await ExtraDetails.findOne({ facultyId: user.facultyId });
        if (!extraDetails || !extraDetails.email) {
            return res.status(404).json({ message: 'Email not found for this user' });
        }

        // Generate and store OTP
        const otp = generateOTP();
        otpStore.set(user.facultyId, {
            otp,
            timestamp: Date.now()
        });

        // Send email with OTP
        const mailOptions = {
            from: emailUser,
            to: extraDetails.email,
            subject: 'Password Reset OTP - Anna University CEG',
            text: `Dear ${extraDetails.fullName},\n\nYour OTP for password reset is: ${otp}\nThis OTP will expire in 5 minutes.\n\nIf you did not request this password reset, please ignore this email.\n\nRegards,\nAnna University CEG`
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log('OTP sent successfully to:', extraDetails.email);
            res.json({ 
                message: 'OTP sent successfully to your registered email',
                email: extraDetails.email // Send back the email for verification
            });
        } catch (emailError) {
            console.error('Error sending email:', emailError);
            res.status(500).json({ 
                message: 'Error sending OTP email',
                error: emailError.message 
            });
        }
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ 
            message: 'Error processing forgot password request',
            error: error.message 
        });
    }
});

// Verify OTP and Reset Password
app.post('/reset-password', async (req, res) => {
    try {
        const { facultyId, otp, newPassword } = req.body;
        
        if (!facultyId || !otp || !newPassword) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if OTP exists and is valid
        const storedData = otpStore.get(facultyId);
        if (!storedData) {
            return res.status(400).json({ message: 'OTP not found or expired' });
        }

        // Check if OTP is expired (5 minutes)
        if (Date.now() - storedData.timestamp > 5 * 60 * 1000) {
            otpStore.delete(facultyId);
            return res.status(400).json({ message: 'OTP expired' });
        }

        // Verify OTP
        if (storedData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        // Find user and update password
        const user = await User.findOne({ facultyId });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.password = newPassword;
        await user.save();

        // Clear OTP from store
        otpStore.delete(facultyId);

        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({ message: 'Error resetting password' });
    }
});

// Get user details by username
app.post('/get-user', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ message: 'Username is required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      facultyId: user.facultyId,
      username: user.username
    });
  } catch (error) {
    console.error('Error getting user:', error);
    res.status(500).json({ message: 'Error getting user details' });
  }
});

app.get('/debug-question-papers', async (req, res) => {
    try {
        const { facultyId, subjectCode } = req.query;
        const papers = await QuestionPaper.find({ facultyId, subjectCode });
        res.json({ count: papers.length, papers });
    } catch (err) {
        console.error('Debug error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Add endpoint for question paper approval
app.post('/api/questionpaper/:id/approval', async (req, res) => {
  try {
    const { id } = req.params;
    const { action } = req.body;

    if (!['accepted', 'rejected'].includes(action)) {
      return res.status(400).json({ success: false, message: 'Invalid action' });
    }

    const questionPaper = await QuestionPaper.findById(id);
    if (!questionPaper) {
      return res.status(404).json({ success: false, message: 'Question paper not found' });
    }

    // Update the question paper status
    questionPaper.adminApproval = action;
    questionPaper.adminApprovalDate = new Date();
    await questionPaper.save();

    res.json({ success: true, message: `Question paper ${action} successfully` });
  } catch (error) {
    console.error('Error processing approval:', error);
    res.status(500).json({ success: false, message: 'Failed to process approval' });
  }
});

// Add endpoint for fetching accepted scrutiny assignments
app.get('/api/accepted-scrutiny-assignments', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const scrutinizerId = req.session.user.facultyId;
        const questionPapers = await QuestionPaper.find({
            scrutinizerId,
            scrutinyRequestStatus: 'accepted'
        }).sort({ createdAt: -1 });

        // Format the response to include necessary details
        const formattedPapers = questionPapers.map(paper => ({
            _id: paper._id,
            subjectCode: paper.subjectCode,
            subjectTitle: paper.subjectTitle,
            department: paper.department,
            semester: paper.semester,
            regulation: paper.regulation,
            time: paper.time,
            maxMarks: paper.maxMarks,
            scrutinyStatus: paper.scrutinyStatus,
            scrutinyDeadline: paper.scrutinyDeadline,
            scrutinyRemarks: paper.scrutinyRemarks
        }));

        res.json(formattedPapers);
    } catch (error) {
        console.error('Error fetching accepted scrutiny assignments:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add endpoint for fetching all scrutiny assignments
app.get('/api/scrutiny-assignments', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'faculty') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const scrutinizerId = req.session.user.facultyId;
        const questionPapers = await QuestionPaper.find({
            scrutinizerId
        }).sort({ createdAt: -1 });

        // Format the response to include necessary details
        const formattedPapers = questionPapers.map(paper => ({
            _id: paper._id,
            subjectCode: paper.subjectCode,
            subjectTitle: paper.subjectTitle,
            department: paper.department,
            semester: paper.semester,
            regulation: paper.regulation,
            time: paper.time,
            maxMarks: paper.maxMarks,
            scrutinyStatus: paper.scrutinyStatus,
            scrutinyRequestStatus: paper.scrutinyRequestStatus,
            scrutinyDeadline: paper.scrutinyDeadline,
            scrutinyRemarks: paper.scrutinyRemarks
        }));

        res.json(formattedPapers);
    } catch (error) {
        console.error('Error fetching scrutiny assignments:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add endpoint for assigning scrutinizer
app.post('/api/questionpaper/:id/assign-scrutinizer', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.role !== 'admin') {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const { scrutinizerId, scrutinizerName, scrutinyDeadline } = req.body;
        const questionPaperId = req.params.id;

        if (!scrutinizerId || !scrutinizerName || !scrutinyDeadline) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const questionPaper = await QuestionPaper.findById(questionPaperId);
        if (!questionPaper) {
            return res.status(404).json({ message: 'Question paper not found' });
        }

        // Update the question paper with scrutinizer details
        questionPaper.scrutinizerId = scrutinizerId;
        questionPaper.scrutinizerName = scrutinizerName;
        questionPaper.scrutinyDeadline = new Date(scrutinyDeadline);
        questionPaper.scrutinyRequestStatus = 'pending';
        questionPaper.scrutinyStatus = 'pending';

        await questionPaper.save();

        res.json({ 
            success: true, 
            message: 'Scrutinizer assigned successfully',
            questionPaper: {
                _id: questionPaper._id,
                subjectCode: questionPaper.subjectCode,
                subjectTitle: questionPaper.subjectTitle,
                scrutinizerId: questionPaper.scrutinizerId,
                scrutinizerName: questionPaper.scrutinizerName,
                scrutinyDeadline: questionPaper.scrutinyDeadline
            }
        });
    } catch (error) {
        console.error('Error assigning scrutinizer:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Debug endpoint to check assignments and papers
app.get('/api/debug-state', async (req, res) => {
    try {
        const assignments = await FacultyAssignment.find({});
        const papers = await QuestionPaper.find({});

        res.json({
            assignmentsCount: assignments.length,
            assignments: assignments,
            papersCount: papers.length,
            papers: papers
        });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug endpoint to check database connection
app.get('/api/debug-db', async (req, res) => {
    try {
        // Check MongoDB connection state
        const state = mongoose.connection.readyState;
        const stateMap = {
            0: 'disconnected',
            1: 'connected',
            2: 'connecting',
            3: 'disconnecting'
        };

        // Count documents in collections
        const questionPapersCount = await QuestionPaper.countDocuments();
        const facultyAssignmentsCount = await FacultyAssignment.countDocuments();
        const usersCount = await User.countDocuments();

        res.json({
            dbState: stateMap[state],
            collections: {
                questionPapers: questionPapersCount,
                facultyAssignments: facultyAssignmentsCount,
                users: usersCount
            }
        });
    } catch (error) {
        console.error('Database check error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});