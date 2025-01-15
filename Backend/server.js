const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Initialize Express App
const app = express();

// Configure Multer for File Upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync('uploads')) {
            fs.mkdirSync('uploads', { recursive: true });
        }
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueFilename = `${uuidv4()}-${file.originalname}`;
        cb(null, uniqueFilename);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// Middleware
app.use(express.json());
app.use(cors({
    origin: ['https://social-ouf.vercel.app', 'http://localhost:5002'],
    credentials: true
}));
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/uploads', express.static('uploads'));

// MongoDB Connection with Retry Logic
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            retryWrites: true
        });
        console.log('MongoDB Connected Successfully');
        await Promise.all([initializeAdmin(), initializeContent()]);
    } catch (err) {
        console.error('MongoDB Connection Error:', err);
        setTimeout(connectDB, 5000); // Retry after 5 seconds
    }
};

connectDB();

// Schemas
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    designation: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    isApproved: { type: Boolean, default: false },
    profilePicture: { type: String, default: 'https://via.placeholder.com/150' },
    connections: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    requests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const contentSchema = new mongoose.Schema({
    content: { type: String, required: true },
    lastUpdated: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Content = mongoose.model('Content', contentSchema);

// Middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

const verifyAdmin = async (req, res, next) => {
    try {
        const admin = await Admin.findById(req.user.id);
        if (!admin) {
            return res.status(403).json({ message: 'Admin access required' });
        }
        next();
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Initialization Functions
const initializeAdmin = async () => {
    const admins = [
        { email: "Socialite@gmail.com", password: "adminSocialite123" },
        { email: "Hitachi@gmail.com", password: "adminHitachi123" }
    ];
    
    try {
        for (const admin of admins) {
            const existingAdmin = await Admin.findOne({ email: admin.email });
            if (!existingAdmin) {
                const hashedPassword = await bcrypt.hash(admin.password, 10);
                await Admin.create({ email: admin.email, password: hashedPassword });
                console.log(`Admin initialized: ${admin.email}`);
            }
        }
    } catch (error) {
        console.error('Admin initialization error:', error);
    }
};

const initializeContent = async () => {
    try {
        const existingContent = await Content.findOne();
        if (!existingContent) {
            await Content.create({ content: 'Welcome to Socialite!' });
            console.log('Default content initialized');
        }
    } catch (error) {
        console.error('Content initialization error:', error);
    }
};

// Routes
// Auth Routes
app.post('/api/auth/register', upload.single('profilePicture'), async (req, res) => {
    try {
        const { name, designation, email, password, confirmPassword } = req.body;

        // Validation
        if (!name || !designation || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        // Handle profile picture
        let profilePicture = 'https://via.placeholder.com/150';
        if (req.file) {
            profilePicture = `/uploads/${req.file.filename}`;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            name,
            designation,
            email,
            password: hashedPassword,
            profilePicture
        });

        res.status(201).json({
            success: true,
            message: 'User registered successfully. Awaiting admin approval.'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration. Please try again.'
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.isApproved) {
            return res.status(403).json({ message: 'Account pending approval' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ 
            token, 
            user: { 
                _id: user._id,
                name: user.name,
                email: user.email,
                designation: user.designation,
                profilePicture: user.profilePicture,
                isApproved: user.isApproved
            } 
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Routes
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });

        if (!admin) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const token = jwt.sign(
            { id: admin._id, isAdmin: true },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({ token });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User Routes
app.get('/api/users/me', authenticate, async (req, res) => {
    try {
        if (req.user.isAdmin) {
            const admin = await Admin.findById(req.user.id);
            if (admin) {
                return res.json({ isAdmin: true });
            }
        }

        const user = await User.findById(req.user.id)
            .select('-password')
            .populate('connections', 'name profilePicture')
            .populate('requests', 'name profilePicture');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ isAdmin: false, ...user.toObject() });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Connection Routes
app.get('/api/members', authenticate, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.id);
        const members = await User.find({
            _id: { $ne: req.user.id },
            isApproved: true
        }).select('name profilePicture _id');

        const membersWithStatus = members.map(member => ({
            ...member.toObject(),
            isConnected: (currentUser.connections || []).includes(member._id),
            requestSent: (member.requests || []).includes(currentUser._id),
            requestReceived: (currentUser.requests || []).includes(member._id)
        }));

        res.json(membersWithStatus);
    } catch (error) {
        console.error('Get members error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Connection management routes
app.post('/api/connections/request/:id', authenticate, async (req, res) => {
    try {
        const toUser = await User.findById(req.params.id);
        const fromUser = await User.findById(req.user.id);

        if (!toUser || !fromUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (toUser.requests.includes(fromUser._id)) {
            return res.status(400).json({ message: 'Request already sent' });
        }

        toUser.requests.push(fromUser._id);
        await toUser.save();

        res.json({ message: 'Connection request sent' });
    } catch (error) {
        console.error('Send request error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/connections/respond/:id', authenticate, async (req, res) => {
    try {
        const { action } = req.body;
        const currentUser = await User.findById(req.user.id);
        const requestUser = await User.findById(req.params.id);

        if (!currentUser || !requestUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        currentUser.requests = currentUser.requests.filter(
            id => id.toString() !== req.params.id
        );

        if (action === 'accept') {
            currentUser.connections.push(req.params.id);
            requestUser.connections.push(req.user.id);
            await requestUser.save();
        }

        await currentUser.save();
        res.json({ message: `Request ${action}ed successfully` });
    } catch (error) {
        console.error('Respond to request error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin management routes
app.get('/api/admin/pending-requests', authenticate, verifyAdmin, async (req, res) => {
    try {
        const pendingUsers = await User.find({ isApproved: false })
            .select('name email designation createdAt');
        res.json(pendingUsers);
    } catch (error) {
        console.error('Get pending requests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/approve/:id', authenticate, verifyAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        user.isApproved = true;
        await user.save();
        res.json({ message: 'User approved successfully' });
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/reject/:id', authenticate, verifyAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User rejected and removed' });
    } catch (error) {
        console.error('Reject user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Content Routes
app.get('/api/content', async (req, res) => {
    try {
        const content = await Content.findOne();
        if (!content) {
            return res.status(404).json({ message: 'Content not found' });
        }
        res.json(content);
    } catch (error) {
        console.error('Get content error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/content', authenticate, verifyAdmin, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content) {
            return res.status(400).json({ message: 'Content is required' });
        }

        const updatedContent = await Content.findOneAndUpdate(
            {},
            { content, lastUpdated: Date.now() },
            { new: true, upsert: true }
        );

        res.json({
            message: 'Content updated successfully',
            content: updatedContent
        });
    } catch (error) {
        console.error('Update content error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start Server
const PORT = process.env.PORT || 5002;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
