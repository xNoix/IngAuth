import express from 'express';
import { registerUser, loginUser, logoutUser, refreshToken, verifyToken } from '../controllers/authController';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', logoutUser);
router.post('/refresh', refreshToken);
router.post('/verify', verifyToken);

export default router;
