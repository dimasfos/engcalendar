// ============================================
// BACKEND - Part 1/4: Dependencies, Configuration & Initialization
// File: server.js
// ============================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
    PORT: process.env.PORT || 3000,
    ADMIN_CODE: process.env.ADMIN_CODE || 'aradeCTIoNicareYdRECO',
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    RATE_LIMIT: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // limit each IP to 100 requests per windowMs
    }
};

// ============================================
// FIREBASE INITIALIZATION
// ============================================

// Initialize Firebase Admin SDK
const serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CERT_URL
};

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// ============================================
// EXPRESS APP SETUP
// ============================================

const app = express();

// Middleware
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || CONFIG.ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit(CONFIG.RATE_LIMIT);
app.use('/api/', limiter);

// Serve static files (index.html)
const path = require('path');
app.use(express.static(__dirname));

// Add this line at the top with other requires
// (if not already there)

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

async function authenticateUser(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No authentication token provided' });
        }
        
        const code = authHeader.substring(7); // Remove 'Bearer ' prefix
        
        // Check if admin code
        if (code === CONFIG.ADMIN_CODE) {
            req.user = {
                role: 'admin',
                code: code
            };
            return next();
        }
        
        // Check if student code
        const studentsSnapshot = await db.collection('students').get();
        let studentFound = false;
        
        studentsSnapshot.forEach(doc => {
            const student = doc.data();
            if (student.accessCode === code) {
                req.user = {
                    role: 'student',
                    code: code,
                    studentId: doc.id,
                    studentName: student.name
                };
                studentFound = true;
            }
        });
        
        if (studentFound) {
            return next();
        }
        
        return res.status(401).json({ error: 'Invalid access code' });
        
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(500).json({ error: 'Authentication failed' });
    }
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function validateStudentData(name, rate) {
    const errors = [];
    
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        errors.push('Student name is required');
    }
    if (name && name.trim().length > 100) {
        errors.push('Student name is too long (max 100 characters)');
    }
    if (typeof rate !== 'number' || isNaN(rate) || rate < 0) {
        errors.push('Rate must be 0 or a positive number');
    }
    if (rate > 100000) {
        errors.push('Rate is unreasonably high');
    }
    
    return {
        valid: errors.length === 0,
        errors: errors
    };
}

function validateEventData(date, time, studentId) {
    const errors = [];
    
    if (!date || typeof date !== 'string') {
        errors.push('Date is required');
    }
    if (!time || typeof time !== 'string') {
        errors.push('Time is required');
    }
    if (!studentId || typeof studentId !== 'string') {
        errors.push('Student ID is required');
    }
    
    return {
        valid: errors.length === 0,
        errors: errors
    };
}

function generateAccessCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}
// ============================================
// BACKEND - Part 2/4: Authentication & Student Management API
// Continue in server.js
// ============================================

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { code } = req.body;
        
        if (!code || typeof code !== 'string') {
            return res.status(400).json({ error: 'Access code is required' });
        }
        
        const trimmedCode = code.trim();
        
        // Check if admin code
        if (trimmedCode === CONFIG.ADMIN_CODE) {
            return res.json({
                success: true,
                user: {
                    role: 'admin',
                    code: trimmedCode
                }
            });
        }
        
        // Check if student code
        const studentsSnapshot = await db.collection('students').get();
        let studentData = null;
        
        studentsSnapshot.forEach(doc => {
            const student = doc.data();
            if (student.accessCode === trimmedCode) {
                studentData = {
                    role: 'student',
                    code: trimmedCode,
                    studentId: doc.id,
                    studentName: student.name
                };
            }
        });
        
        if (studentData) {
            return res.json({
                success: true,
                user: studentData
            });
        }
        
        return res.status(401).json({ error: 'Invalid access code' });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Validate token endpoint
app.get('/api/auth/validate', authenticateUser, (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// ============================================
// STUDENT MANAGEMENT ENDPOINTS
// ============================================

// Get all students (admin) or single student (student role)
app.get('/api/students', authenticateUser, async (req, res) => {
    try {
        const studentsSnapshot = await db.collection('students').get();
        const students = [];
        
        studentsSnapshot.forEach(doc => {
            const student = {
                id: doc.id,
                ...doc.data()
            };
            
            // Filter based on role
            if (req.user.role === 'admin') {
                students.push(student);
            } else if (req.user.role === 'student' && doc.id === req.user.studentId) {
                students.push(student);
            }
        });
        
        res.json({ students });
        
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});

// Get single student by ID
app.get('/api/students/:id', authenticateUser, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check permissions
        if (req.user.role === 'student' && req.user.studentId !== id) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const studentDoc = await db.collection('students').doc(id).get();
        
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        res.json({
            id: studentDoc.id,
            ...studentDoc.data()
        });
        
    } catch (error) {
        console.error('Error fetching student:', error);
        res.status(500).json({ error: 'Failed to fetch student' });
    }
});

// Create new student (admin only)
app.post('/api/students', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { name, rate } = req.body;
        
        // Validate input
        const validation = validateStudentData(name, rate);
        if (!validation.valid) {
            return res.status(400).json({ 
                error: 'Invalid student data', 
                details: validation.errors 
            });
        }
        
        const studentId = Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
        
        const studentData = {
            name: name.trim(),
            rate: rate,
            accessCode: null
        };
        
        await db.collection('students').doc(studentId).set(studentData);
        
        // Initialize related collections
        await db.collection('paidLessons').doc(studentId).set({ count: 0 });
        await db.collection('studentNotes').doc(studentId).set({ notes: '' });
        
        res.status(201).json({
            success: true,
            student: {
                id: studentId,
                ...studentData
            }
        });
        
    } catch (error) {
        console.error('Error creating student:', error);
        res.status(500).json({ error: 'Failed to create student' });
    }
});

// Update student (admin only)
app.put('/api/students/:id', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, rate, accessCode } = req.body;
        
        const studentDoc = await db.collection('students').doc(id).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        const updateData = {};
        
        if (name !== undefined) {
            if (!name || name.trim().length === 0) {
                return res.status(400).json({ error: 'Student name cannot be empty' });
            }
            updateData.name = name.trim();
        }
        
        if (rate !== undefined) {
            if (typeof rate !== 'number' || rate < 0) {
                return res.status(400).json({ error: 'Invalid rate value' });
            }
            updateData.rate = rate;
        }
        
        if (accessCode !== undefined) {
            updateData.accessCode = accessCode;
        }
        
        await db.collection('students').doc(id).update(updateData);
        
        const updatedDoc = await db.collection('students').doc(id).get();
        
        res.json({
            success: true,
            student: {
                id: updatedDoc.id,
                ...updatedDoc.data()
            }
        });
        
    } catch (error) {
        console.error('Error updating student:', error);
        res.status(500).json({ error: 'Failed to update student' });
    }
});

// Delete student (admin only)
app.delete('/api/students/:id', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Delete student document
        await db.collection('students').doc(id).delete();
        
        // Delete related data
        await db.collection('paidLessons').doc(id).delete();
        await db.collection('studentNotes').doc(id).delete();
        
        // Delete all events for this student
        const eventsSnapshot = await db.collection('events')
            .where('studentId', '==', id)
            .get();
        
        const batch = db.batch();
        eventsSnapshot.forEach(doc => {
            batch.delete(doc.ref);
        });
        await batch.commit();
        
        res.json({ 
            success: true, 
            message: 'Student and related data deleted successfully' 
        });
        
    } catch (error) {
        console.error('Error deleting student:', error);
        res.status(500).json({ error: 'Failed to delete student' });
    }
});

// Generate access code for student (admin only)
app.post('/api/students/:id/generate-code', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const studentDoc = await db.collection('students').doc(id).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        const newCode = generateAccessCode();
        
        await db.collection('students').doc(id).update({
            accessCode: newCode
        });
        
        res.json({
            success: true,
            accessCode: newCode
        });
        
    } catch (error) {
        console.error('Error generating access code:', error);
        res.status(500).json({ error: 'Failed to generate access code' });
    }
});
// ============================================
// BACKEND - Part 3/4: Events, Payments, Notes & Announcements API
// Continue in server.js
// ============================================

// ============================================
// EVENTS ENDPOINTS
// ============================================

// Get all events (filtered by role)
app.get('/api/events', authenticateUser, async (req, res) => {
    try {
        let eventsQuery = db.collection('events');
        
        // Filter by student if student role
        if (req.user.role === 'student') {
            eventsQuery = eventsQuery.where('studentId', '==', req.user.studentId);
        }
        
        const eventsSnapshot = await eventsQuery.get();
        const events = [];
        
        eventsSnapshot.forEach(doc => {
            events.push({
                id: doc.id,
                ...doc.data()
            });
        });
        
        res.json({ events });
        
    } catch (error) {
        console.error('Error fetching events:', error);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// Create new event (admin only)
app.post('/api/events', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { date, time, studentId, notes } = req.body;
        
        // Validate input
        const validation = validateEventData(date, time, studentId);
        if (!validation.valid) {
            return res.status(400).json({ 
                error: 'Invalid event data', 
                details: validation.errors 
            });
        }
        
        // Check if student exists
        const studentDoc = await db.collection('students').doc(studentId).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        const eventId = Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
        
        const eventData = {
            date: date,
            time: time,
            studentId: studentId,
            notes: notes || ''
        };
        
        await db.collection('events').doc(eventId).set(eventData);
        
        res.status(201).json({
            success: true,
            event: {
                id: eventId,
                ...eventData
            }
        });
        
    } catch (error) {
        console.error('Error creating event:', error);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// Update event (admin only)
app.put('/api/events/:id', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { date, time, studentId, notes } = req.body;
        
        const eventDoc = await db.collection('events').doc(id).get();
        if (!eventDoc.exists) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        const updateData = {};
        
        if (date !== undefined) updateData.date = date;
        if (time !== undefined) updateData.time = time;
        if (studentId !== undefined) {
            // Verify student exists
            const studentDoc = await db.collection('students').doc(studentId).get();
            if (!studentDoc.exists) {
                return res.status(404).json({ error: 'Student not found' });
            }
            updateData.studentId = studentId;
        }
        if (notes !== undefined) updateData.notes = notes;
        
        await db.collection('events').doc(id).update(updateData);
        
        const updatedDoc = await db.collection('events').doc(id).get();
        
        res.json({
            success: true,
            event: {
                id: updatedDoc.id,
                ...updatedDoc.data()
            }
        });
        
    } catch (error) {
        console.error('Error updating event:', error);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

// Delete event (admin only)
app.delete('/api/events/:id', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.collection('events').doc(id).delete();
        
        res.json({ 
            success: true, 
            message: 'Event deleted successfully' 
        });
        
    } catch (error) {
        console.error('Error deleting event:', error);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

// ============================================
// PAID LESSONS (PAYMENTS) ENDPOINTS
// ============================================

// Get all paid lessons
app.get('/api/payments', authenticateUser, async (req, res) => {
    try {
        const paymentsSnapshot = await db.collection('paidLessons').get();
        const payments = {};
        
        paymentsSnapshot.forEach(doc => {
            // Filter by student if student role
            if (req.user.role === 'admin' || doc.id === req.user.studentId) {
                payments[doc.id] = doc.data().count || 0;
            }
        });
        
        res.json({ payments });
        
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

// Update paid lessons for a student (admin only)
app.put('/api/payments/:studentId', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { studentId } = req.params;
        const { count } = req.body;
        
        if (typeof count !== 'number' || count < 0) {
            return res.status(400).json({ error: 'Invalid count value' });
        }
        
        // Check if student exists
        const studentDoc = await db.collection('students').doc(studentId).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        await db.collection('paidLessons').doc(studentId).set({ count: count });
        
        res.json({
            success: true,
            studentId: studentId,
            count: count
        });
        
    } catch (error) {
        console.error('Error updating paid lessons:', error);
        res.status(500).json({ error: 'Failed to update paid lessons' });
    }
});

// Add paid lessons (admin only)
app.post('/api/payments/:studentId/add', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { studentId } = req.params;
        const { lessons } = req.body;
        
        if (typeof lessons !== 'number' || lessons <= 0) {
            return res.status(400).json({ error: 'Invalid lessons value' });
        }
        
        // Check if student exists
        const studentDoc = await db.collection('students').doc(studentId).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        // Get current count
        const paidDoc = await db.collection('paidLessons').doc(studentId).get();
        const currentCount = paidDoc.exists ? (paidDoc.data().count || 0) : 0;
        const newCount = currentCount + lessons;
        
        await db.collection('paidLessons').doc(studentId).set({ count: newCount });
        
        res.json({
            success: true,
            studentId: studentId,
            count: newCount,
            added: lessons
        });
        
    } catch (error) {
        console.error('Error adding paid lessons:', error);
        res.status(500).json({ error: 'Failed to add paid lessons' });
    }
});

// ============================================
// STUDENT NOTES ENDPOINTS
// ============================================

// Get all student notes
app.get('/api/notes', authenticateUser, async (req, res) => {
    try {
        const notesSnapshot = await db.collection('studentNotes').get();
        const notes = {};
        
        notesSnapshot.forEach(doc => {
            // Filter by student if student role
            if (req.user.role === 'admin' || doc.id === req.user.studentId) {
                notes[doc.id] = doc.data().notes || '';
            }
        });
        
        res.json({ notes });
        
    } catch (error) {
        console.error('Error fetching notes:', error);
        res.status(500).json({ error: 'Failed to fetch notes' });
    }
});

// Get notes for specific student
app.get('/api/notes/:studentId', authenticateUser, async (req, res) => {
    try {
        const { studentId } = req.params;
        
        // Check permissions
        if (req.user.role === 'student' && req.user.studentId !== studentId) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const notesDoc = await db.collection('studentNotes').doc(studentId).get();
        
        res.json({
            studentId: studentId,
            notes: notesDoc.exists ? (notesDoc.data().notes || '') : ''
        });
        
    } catch (error) {
        console.error('Error fetching notes:', error);
        res.status(500).json({ error: 'Failed to fetch notes' });
    }
});

// Update student notes (admin only)
app.put('/api/notes/:studentId', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { studentId } = req.params;
        const { notes } = req.body;
        
        if (typeof notes !== 'string') {
            return res.status(400).json({ error: 'Notes must be a string' });
        }
        
        // Check if student exists
        const studentDoc = await db.collection('students').doc(studentId).get();
        if (!studentDoc.exists) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        await db.collection('studentNotes').doc(studentId).set({ notes: notes });
        
        res.json({
            success: true,
            studentId: studentId,
            notes: notes
        });
        
    } catch (error) {
        console.error('Error updating notes:', error);
        res.status(500).json({ error: 'Failed to update notes' });
    }
});

// ============================================
// ANNOUNCEMENTS ENDPOINTS
// ============================================

// Get current announcement
app.get('/api/announcements/current', authenticateUser, async (req, res) => {
    try {
        const announcementDoc = await db.collection('announcements').doc('current').get();
        
        if (!announcementDoc.exists) {
            return res.json({
                title: '',
                message: '',
                active: false
            });
        }
        
        res.json(announcementDoc.data());
        
    } catch (error) {
        console.error('Error fetching announcement:', error);
        res.status(500).json({ error: 'Failed to fetch announcement' });
    }
});

// Create/Update announcement (admin only)
app.post('/api/announcements', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { title, message, active } = req.body;
        
        const announcementData = {
            title: title || '',
            message: message || '',
            active: active !== undefined ? active : false,
            updatedAt: new Date().toISOString()
        };
        
        await db.collection('announcements').doc('current').set(announcementData);
        
        res.json({
            success: true,
            announcement: announcementData
        });
        
    } catch (error) {
        console.error('Error saving announcement:', error);
        res.status(500).json({ error: 'Failed to save announcement' });
    }
});

// Delete announcement (admin only)
app.delete('/api/announcements/current', authenticateUser, requireAdmin, async (req, res) => {
    try {
        await db.collection('announcements').doc('current').set({
            title: '',
            message: '',
            active: false,
            updatedAt: new Date().toISOString()
        });
        
        res.json({ 
            success: true, 
            message: 'Announcement cleared' 
        });
        
    } catch (error) {
        console.error('Error deleting announcement:', error);
        res.status(500).json({ error: 'Failed to delete announcement' });
    }
});
// ============================================
// BACKEND - Part 4/4: Settings, Error Handling & Server Startup
// Continue in server.js
// ============================================

// ============================================
// SETTINGS ENDPOINTS
// ============================================

// Get app settings
app.get('/api/settings', authenticateUser, async (req, res) => {
    try {
        const settingsDoc = await db.collection('settings').doc('appSettings').get();
        
        if (!settingsDoc.exists) {
            return res.json({
                isDarkMode: false
            });
        }
        
        res.json(settingsDoc.data());
        
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update app settings (admin only)
app.put('/api/settings', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { isDarkMode } = req.body;
        
        const settingsData = {
            isDarkMode: isDarkMode !== undefined ? isDarkMode : false
        };
        
        await db.collection('settings').doc('appSettings').set(settingsData);
        
        res.json({
            success: true,
            settings: settingsData
        });
        
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ============================================
// BULK OPERATIONS (COPY EVENTS)
// ============================================

// Copy events (week or month) - Admin only
app.post('/api/events/copy', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const { copyType, fromDate, toDate } = req.body;
        
        if (!copyType || !fromDate || !toDate) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }
        
        const from = new Date(fromDate);
        const to = new Date(toDate);
        
        let eventsToCopy = [];
        const newEvents = [];
        
        if (copyType === 'week') {
            // Get week start (Sunday)
            const fromWeekStart = new Date(from);
            fromWeekStart.setDate(from.getDate() - from.getDay());
            
            const fromWeekEnd = new Date(fromWeekStart);
            fromWeekEnd.setDate(fromWeekStart.getDate() + 6);
            
            const fromWeekStartStr = fromWeekStart.toISOString().split('T')[0];
            const fromWeekEndStr = fromWeekEnd.toISOString().split('T')[0];
            
            // Get events in the week range
            const eventsSnapshot = await db.collection('events').get();
            eventsSnapshot.forEach(doc => {
                const event = doc.data();
                if (event.date >= fromWeekStartStr && event.date <= fromWeekEndStr) {
                    eventsToCopy.push({ id: doc.id, ...event });
                }
            });
            
            const dayDiff = Math.floor((to - from) / (1000 * 60 * 60 * 24));
            const weekDiff = Math.floor(dayDiff / 7) * 7;
            
            for (const event of eventsToCopy) {
                const eventDate = new Date(event.date);
                const newDate = new Date(eventDate);
                newDate.setDate(eventDate.getDate() + weekDiff);
                
                const newDateStr = newDate.toISOString().split('T')[0];
                
                // Check if event already exists
                const existingSnapshot = await db.collection('events')
                    .where('date', '==', newDateStr)
                    .where('time', '==', event.time)
                    .get();
                
                if (existingSnapshot.empty) {
                    const newEventId = Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
                    const newEventData = {
                        date: newDateStr,
                        time: event.time,
                        studentId: event.studentId,
                        notes: event.notes || ''
                    };
                    
                    await db.collection('events').doc(newEventId).set(newEventData);
                    newEvents.push({ id: newEventId, ...newEventData });
                    
                    // Small delay to ensure unique IDs
                    await new Promise(resolve => setTimeout(resolve, 10));
                }
            }
            
        } else if (copyType === 'month') {
            const fromMonth = from.getMonth();
            const fromYear = from.getFullYear();
            const monthStr = `${fromYear}-${String(fromMonth + 1).padStart(2, '0')}`;
            
            // Get all events from the month
            const eventsSnapshot = await db.collection('events').get();
            eventsSnapshot.forEach(doc => {
                const event = doc.data();
                if (event.date.startsWith(monthStr)) {
                    eventsToCopy.push({ id: doc.id, ...event });
                }
            });
            
            const toMonth = to.getMonth();
            const toYear = to.getFullYear();
            const monthDiff = (toYear - fromYear) * 12 + (toMonth - fromMonth);
            
            for (const event of eventsToCopy) {
                const eventDate = new Date(event.date);
                const newDate = new Date(eventDate);
                newDate.setMonth(eventDate.getMonth() + monthDiff);
                
                // Check if the day exists in the new month
                if (newDate.getMonth() === (eventDate.getMonth() + monthDiff + 12) % 12) {
                    const newDateStr = newDate.toISOString().split('T')[0];
                    
                    // Check if event already exists
                    const existingSnapshot = await db.collection('events')
                        .where('date', '==', newDateStr)
                        .where('time', '==', event.time)
                        .get();
                    
                    if (existingSnapshot.empty) {
                        const newEventId = Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
                        const newEventData = {
                            date: newDateStr,
                            time: event.time,
                            studentId: event.studentId,
                            notes: event.notes || ''
                        };
                        
                        await db.collection('events').doc(newEventId).set(newEventData);
                        newEvents.push({ id: newEventId, ...newEventData });
                        
                        // Small delay to ensure unique IDs
                        await new Promise(resolve => setTimeout(resolve, 10));
                    }
                }
            }
        }
        
        res.json({
            success: true,
            copiedCount: newEvents.length,
            events: newEvents
        });
        
    } catch (error) {
        console.error('Error copying events:', error);
        res.status(500).json({ error: 'Failed to copy events' });
    }
});

// ============================================
// HEALTH CHECK & ROOT ENDPOINTS
// ============================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        service: 'EduCalendar API'
    });
});


// ============================================
// ERROR HANDLING
// ============================================


// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ============================================
// SERVER STARTUP
// ============================================

const server = app.listen(CONFIG.PORT, () => {
    console.log('\n================================================');
    console.log('🚀 EduCalendar Pro API Server Started');
    console.log('================================================');
    console.log(`📍 Server running on port: ${CONFIG.PORT}`);
    console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 CORS enabled for: ${CONFIG.ALLOWED_ORIGINS.join(', ')}`);
    console.log(`⏰ Started at: ${new Date().toISOString()}`);
    console.log('================================================\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('\nSIGINT signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});

// Serve index.html for root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle 404s for non-API routes by serving index.html
app.use((req, res, next) => {
    if (!req.path.startsWith('/api')) {
        res.sendFile(path.join(__dirname, 'index.html'));
    } else {
        next();
    }
});
module.exports = app;