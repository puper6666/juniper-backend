const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Подключение к MongoDB Atlas
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://kavyn522_db_user:<db_password>@cluster0.ambn0af.mongodb.net/juniper_vpn?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Успешное подключение к базе данных MongoDB Atlas'))
  .catch(err => {
    console.error('❌ Ошибка подключения к MongoDB:', err.message);
    console.log('ℹ️ Подсказка: убедитесь, что в файле backend/.env заменен <db_password> на реальный пароль базы.');
  });

// Схема пользователя JuniperVPN
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  subscriptionExpiresAt: { 
    type: Date, 
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 дней при регистрации
  },
  isActive: { type: Boolean, default: true },
  notes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);

// Встроенные защищенные серверы JuniperVPN (Швеция и Польша)
const SERVERS = [
  {
    id: "sweden",
    name: "Швеция",
    flag: "🇸🇪",
    address: "4.223.130.97",
    port: 443,
    uuid: "64883815-9160-4a79-97b7-95dd0f756688",
    publicKey: "Q2nhHmnKUCtmc1EHjj-BYaY1QYoxlWHyAjz7qO_6ulc",
    shortId: "3e8e912845c4f21f",
    sni: "dl.google.com",
    flow: "xtls-rprx-vision",
    fingerprint: "chrome"
  },
  {
    id: "poland",
    name: "Польша",
    flag: "🇵🇱",
    address: "20.215.68.67",
    port: 15001,
    uuid: "a57023cc-d26e-4283-9028-d54d69bf620b",
    publicKey: "vsm5YHcFaPJliJ1x8WjVqQ3vEPMlSLKi0CCH31_jNDI",
    shortId: "6ba85179e30d4fc2",
    sni: "www.suffolk.edu",
    flow: "xtls-rprx-vision",
    fingerprint: "chrome"
  }
];

// Middleware проверки JWT токена
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется токен авторизации' });

  jwt.verify(token, process.env.JWT_SECRET || 'juniper_secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Токен недействителен или срок его действия истек' });
    req.user = user;
    next();
  });
}

// -------------------------------------------------------------
// API ДЛЯ МОБИЛЬНОГО ПРИЛОЖЕНИЯ
// -------------------------------------------------------------

// 1. Регистрация нового пользователя
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Укажите имя пользователя и пароль' });
    }

    if (username.length < 3 || password.length < 4) {
      return res.status(400).json({ error: 'Логин от 3 символов, пароль от 4 символов' });
    }

    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким логином уже зарегистрирован' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.toLowerCase(),
      password: hashedPassword,
      subscriptionExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 дней по умолчанию
    });

    await user.save();
    console.log(`[AUTH] Зарегистрирован новый пользователь: ${user.username}`);
    res.status(201).json({ message: 'Регистрация успешна! Теперь вы можете войти в аккаунт.' });
  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// 2. Авторизация (Вход)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Введите логин и пароль' });
    }

    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) {
      return res.status(400).json({ error: 'Пользователь не найден' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Неверный пароль' });
    }

    user.lastLoginAt = new Date();
    await user.save();

    const now = new Date();
    const isSubActive = user.isActive && user.subscriptionExpiresAt > now;
    const remainingDays = Math.max(0, Math.ceil((user.subscriptionExpiresAt - now) / (1000 * 60 * 60 * 24)));

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'juniper_secret',
      { expiresIn: '60d' }
    );

    res.json({
      token,
      username: user.username,
      subscriptionExpiresAt: user.subscriptionExpiresAt,
      isSubActive,
      remainingDays,
      message: isSubActive ? 'Вход выполнен успешно' : 'Срок действия вашей подписки истёк'
    });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// 3. Проверка статуса подписки
app.get('/api/auth/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const now = new Date();
    const isSubActive = user.isActive && user.subscriptionExpiresAt > now;
    const remainingDays = Math.max(0, Math.ceil((user.subscriptionExpiresAt - now) / (1000 * 60 * 60 * 24)));

    res.json({
      username: user.username,
      subscriptionExpiresAt: user.subscriptionExpiresAt,
      isSubActive,
      remainingDays
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения статуса' });
  }
});

// 4. Получение списка серверов для защищенного соединения
app.get('/api/vpn/servers', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const now = new Date();
    if (!user.isActive || user.subscriptionExpiresAt <= now) {
      return res.status(403).json({ error: 'Подписка истекла. Доступ к серверам ограничен.' });
    }

    res.json({ servers: SERVERS });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка загрузки серверов' });
  }
});

// -------------------------------------------------------------
// ПАНЕЛЬ АДМИНИСТРАТОРА (Управление пользователями и подписками)
// -------------------------------------------------------------

function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
  if (adminKey !== (process.env.ADMIN_PASSWORD || 'juniperadmin2026')) {
    return res.status(403).json({ error: 'Неверный ключ администратора' });
  }
  next();
}

// Список всех пользователей
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения пользователей' });
  }
});

// Продление подписки пользователю (на N дней)
app.post('/api/admin/extend', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const currentExpiry = user.subscriptionExpiresAt > new Date() ? user.subscriptionExpiresAt : new Date();
    user.subscriptionExpiresAt = new Date(currentExpiry.getTime() + (parseInt(days) || 30) * 24 * 60 * 60 * 1000);
    user.isActive = true;
    await user.save();

    res.json({ message: `Подписка для ${user.username} успешно продлена на ${days} дней!`, user });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка продления подписки' });
  }
});

// Блокировка / разблокировка
app.post('/api/admin/toggle-status', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    user.isActive = !user.isActive;
    await user.save();

    res.json({ message: `Статус пользователя изменен на: ${user.isActive ? 'Активен' : 'Заблокирован'}`, user });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка смены статуса' });
  }
});

// Удаление пользователя
app.delete('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'Пользователь удален' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка удаления' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`=========================================`);
  console.log(`🌲 JuniperVPN Backend запущен на порту ${PORT}`);
  console.log(`🌍 Админ-панель доступна по адресу: http://localhost:${PORT}/admin.html`);
  console.log(`=========================================`);
});
