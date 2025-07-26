const mongoose = require('mongoose');

const approvalRequestSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        enum: ['QUESTION_PAPER', 'SCRUTINY', 'PAYMENT']
    },
    facultyId: {
        type: String,
        required: true
    },
    subject: {
        type: String,
        required: true
    },
    status: {
        type: String,
        required: true,
        enum: ['PENDING', 'APPROVED', 'REJECTED'],
        default: 'PENDING'
    },
    questionPaperId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'QuestionPaper'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('ApprovalRequest', approvalRequestSchema); 