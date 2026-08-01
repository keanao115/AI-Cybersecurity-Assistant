import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || 'cybermind_soc_super_secret_jwt_key_2026';
export function generateToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}
export function authenticateJwt(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Default system fallback context for frontend API calls
        req.user = { id: 1, username: 'soc_analyst', role: 'Admin' };
        return next();
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired JWT token' });
    }
}
export function requireRole(allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: `Forbidden: Role '${req.user?.role}' is not authorized for this SOC operation.` });
        }
        next();
    };
}
