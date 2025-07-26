const mongoose = require('mongoose');

const questionPaperSchema = new mongoose.Schema({
    facultyId: {
        type: String,
        required: true
    },
    subjectCode: {
        type: String,
        required: true
    },
    subjectTitle: {
        type: String,
        required: true
    },
    scrutinyRequestStatus: {
        type: String,
        enum: ['pending', 'accepted', 'rejected'],
        default: 'pending'
    },
    scrutinyDeadline: {
        type: Date,
        default: null
    },
    scrutinyNotificationSent: {
        type: Boolean,
        default: false
    },
    submissionDeadline: {
        type: Date,
        default: null
    },
    submissionNotificationSent: {
        type: Boolean,
        default: false
    }
});

module.exports = mongoose.model('QuestionPaper', questionPaperSchema); 