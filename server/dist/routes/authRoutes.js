import { Router } from 'express';
import { generateToken } from '../middleware/auth.js';
import { memoryDb } from '../db/client.js';
export const authRouter = Router();
authRouter.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    // Simplified demo authentication
    const user = memoryDb.users.find(u => u.username === username) || {
        id: 1,
        username: username || 'soc_analyst',
        role: 'Admin'
    };
    const token = generateToken({ id: user.id, username: user.username, role: user.role });
    return res.json({
        message: 'Authentication successful',
        token,
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    });
});
authRouter.get('/me', (req, res) => {
    return res.json({
        user: req.user || { id: 1, username: 'soc_analyst', role: 'Admin' }
    });
});
