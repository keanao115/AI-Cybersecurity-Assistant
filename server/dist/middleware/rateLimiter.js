import rateLimit from 'express-rate-limit';
export const apiRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // Limit each IP to 300 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests from this IP address to the SOC API. Please try again after 15 minutes.'
    }
});
export const ingestRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // Limit ingestion to 100 uploads per window
    standardHeaders: true,
    message: {
        error: 'Log ingestion rate limit exceeded. Please throttle log stream uploads.'
    }
});
