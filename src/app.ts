import express from 'express';
import cors from 'cors';
import authRoutes from './routes/authRoutes';
import errorHandler from './middlewares/errorHandler';
import logger from './utils/logger';
import cookieParser from 'cookie-parser';
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(logger);

app.use(cors({
    origin: 'http://localhost:3000', // Reemplaza con el dominio de tu aplicación Next.js
    credentials: true,
  }));  

app.use('/api/auth', authRoutes);
app.use(errorHandler);

export default app;
