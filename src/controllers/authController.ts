import { Request, Response } from 'express';
import prisma from '../models/userModel';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import redisClient from '../utils/redisClient';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

export const registerUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const { email, name, password, roleId } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword,
        roleId: Number(roleId),
      },
    });

    const token = jwt.sign({ userId: user.id, role: user.roleId }, JWT_SECRET, { expiresIn: '1h' });

    // Store token in Redis
    await redisClient.set(token, JSON.stringify({ userId: user.id, role: user.roleId }), 'EX', 3600);

    // Set the token in HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // set to true in production
      maxAge: 3600 * 1000, // 1 hour
    });

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error in registerUser:', error); // Log the error for debugging
    return res.status(500).json({ error: 'Failed to register user', details: error });
  }
};

export const loginUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const { email, password } = req.body;

    // Busca el usuario en la base de datos
    const user = await prisma.user.findUnique({
      where: { email },
      include: { role: true },
    });

    // Verifica si el usuario existe y si la contraseña es correcta
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Genera un token JWT
    const token = jwt.sign({ userId: user.id, role: user.role.name }, JWT_SECRET, { expiresIn: '1h' });

    // Almacena el token en Redis
    await redisClient.set(token, JSON.stringify({ userId: user.id, role: user.role.name }), 'EX', 3600);

    // Establece la cookie HTTP-only con el token
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Usa true en producción
      maxAge: 3600 * 1000, // 1 hora
    });

    return res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error('Error in loginUser:', error); // Loguea el error para depuración
    return res.status(500).json({ error: 'Failed to login user', details: error });
  }
};

export const logoutUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const token = req.cookies.token;

    if (token) {
      // Delete token from Redis
      await redisClient.del(token);
    }

    // Clear the cookie
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });

    return res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Error in logoutUser:', error); // Log the error for debugging
    return res.status(500).json({ error: 'Failed to logout user', details: error });
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<Response> => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Token missing' });
    }

    const payload = jwt.verify(token, JWT_SECRET) as { userId: number; role: string };
    if (!payload) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Generate new token
    const newToken = jwt.sign({ userId: payload.userId, role: payload.role }, JWT_SECRET, { expiresIn: '1h' });

    // Store new token in Redis and delete old token
    await redisClient.set(newToken, JSON.stringify({ userId: payload.userId, role: payload.role }), 'EX', 3600);
    await redisClient.del(token);

    return res.status(200).json({ token: newToken });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to refresh token' });
  }
};

export const verifyToken = async (req: Request, res: Response): Promise<Response> => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Token missing' });
    }

    const payload = jwt.verify(token, JWT_SECRET) as { userId: number; role: string };
    if (!payload) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    return res.status(200).json({ message: 'Token is valid', userId: payload.userId, role: payload.role });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to verify token' });
  }
};
