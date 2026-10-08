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
  });

// Схема пользователя JuniperVPN
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  subscriptionExpiresAt: { 
    type: Date, 
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  },
  isActive: { type: Boolean, default: true },
  isAdmin: { type: Boolean, default: false },
  notes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);

// Схема VPN Сервера (VLESS Reality)
const ServerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  flag: { type: String, default: '🌐' },
  address: { type: String, required: true },
  port: { type: Number, required: true },
  uuid: { type: String, required: true },
  publicKey: { type: String, required: true },
  shortId: { type: String, default: '' },
  sni: { type: String, default: '' },
  flow: { type: String, default: 'xtls-rprx-vision' },
  fingerprint: { type: String, default: 'chrome' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const ServerModel = mongoose.model('Server', ServerSchema);

// Вспомогательная функция парсинга vless:// ссылки
function parseVlessUri(uri) {
  try {
    const trimmed = uri.trim();
    if (!trimmed.startsWith('vless://')) return null;

    const url = new URL(trimmed);
    const uuid = url.username;
    const address = url.hostname;
    const port = parseInt(url.port) || 443;
    const params = url.searchParams;

    const flow = params.get('flow') || 'xtls-rprx-vision';
    const sni = params.get('sni') || '';
    const fingerprint = params.get('fp') || 'chrome';
    const publicKey = params.get('pbk') || '';
    const shortId = params.get('sid') || '';
    const rawName = decodeURIComponent(url.hash ? url.hash.substring(1) : '');

    if (!uuid || !address || !publicKey) return null;

    return {
      uuid,
      address,
      port,
      flow,
      sni,
      fingerprint,
      publicKey,
      shortId,
      rawName
    };
  } catch (e) {
    return null;
  }
}

// Запасные серверы (если база временно недоступна)
const FALLBACK_SERVERS = [
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

// Middleware администратора
async function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
  if (adminKey && adminKey === (process.env.ADMIN_PASSWORD || 'juniperadmin2026')) {
    return next();
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуются права администратора' });

  jwt.verify(token, process.env.JWT_SECRET || 'juniper_secret', async (err, payload) => {
    if (err) return res.status(403).json({ error: 'Токен недействителен' });
    try {
      const user = await User.findById(payload.id);
      if (!user || (!user.isAdmin && user.username !== 'kavyn')) {
        return res.status(403).json({ error: 'Доступ разрешен только администраторам' });
      }
      req.user = user;
      next();
    } catch (e) {
      res.status(500).json({ error: 'Ошибка проверки прав' });
    }
  });
}

// -------------------------------------------------------------
// API АВТОРИЗАЦИИ И СТАТУСА
// -------------------------------------------------------------

// 1. Вход
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Введите логин и пароль' });
    }

    const user = await User.findOne({ username: username.toLowerCase().trim() });
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
    const isAdmin = Boolean(user.isAdmin || user.username === 'kavyn');

    const token = jwt.sign(
      { id: user._id, username: user.username, isAdmin },
      process.env.JWT_SECRET || 'juniper_secret',
      { expiresIn: '60d' }
    );

    res.json({
      token,
      username: user.username,
      subscriptionExpiresAt: user.subscriptionExpiresAt,
      isSubActive,
      remainingDays,
      isAdmin,
      message: isSubActive ? 'Вход выполнен успешно' : 'Срок действия вашей подписки истёк'
    });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// 2. Статус подписки
app.get('/api/auth/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const now = new Date();
    const isSubActive = user.isActive && user.subscriptionExpiresAt > now;
    const remainingDays = Math.max(0, Math.ceil((user.subscriptionExpiresAt - now) / (1000 * 60 * 60 * 24)));
    const isAdmin = Boolean(user.isAdmin || user.username === 'kavyn');

    res.json({
      username: user.username,
      subscriptionExpiresAt: user.subscriptionExpiresAt,
      isSubActive,
      remainingDays,
      isAdmin
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения статуса' });
  }
});

// 3. Список серверов для пользователей с подпиской
app.get('/api/vpn/servers', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const now = new Date();
    if (!user.isActive || user.subscriptionExpiresAt <= now) {
      return res.status(403).json({ error: 'Подписка истекла. Доступ к серверам ограничен.' });
    }

    const dbServers = await ServerModel.find({ isActive: true }).sort({ createdAt: 1 });
    if (dbServers && dbServers.length > 0) {
      const formatted = dbServers.map(s => ({
        id: s._id.toString(),
        name: s.name,
        flag: s.flag || '🌐',
        address: s.address,
        port: s.port,
        uuid: s.uuid,
        publicKey: s.publicKey,
        shortId: s.shortId || '',
        sni: s.sni || '',
        flow: s.flow || 'xtls-rprx-vision',
        fingerprint: s.fingerprint || 'chrome'
      }));
      return res.json({ servers: formatted });
    }

    res.json({ servers: FALLBACK_SERVERS });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка загрузки серверов' });
  }
});

// -------------------------------------------------------------
// ПАНЕЛЬ АДМИНИСТРАТОРА: ПОЛЬЗОВАТЕЛИ
// -------------------------------------------------------------

// Список всех пользователей
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения пользователей' });
  }
});

// Создание пользователя
app.post('/api/admin/create-user', requireAdmin, async (req, res) => {
  try {
    const { username, password, days, isAdmin } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Укажите логин и пароль' });
    }

    const existingUser = await User.findOne({ username: username.toLowerCase().trim() });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const subDays = parseInt(days) || 30;
    const expiry = new Date(Date.now() + subDays * 24 * 60 * 60 * 1000);

    const user = new User({
      username: username.toLowerCase().trim(),
      password: hashedPassword,
      subscriptionExpiresAt: expiry,
      isActive: true,
      isAdmin: Boolean(isAdmin)
    });

    await user.save();
    res.status(201).json({ message: `Пользователь ${user.username} успешно создан!`, user: {
      _id: user._id,
      username: user.username,
      subscriptionExpiresAt: user.subscriptionExpiresAt,
      isActive: user.isActive,
      isAdmin: user.isAdmin
    }});
  } catch (error) {
    res.status(500).json({ error: 'Ошибка создания пользователя' });
  }
});

// Продление подписки
app.post('/api/admin/extend', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const currentExpiry = user.subscriptionExpiresAt > new Date() ? user.subscriptionExpiresAt : new Date();
    user.subscriptionExpiresAt = new Date(currentExpiry.getTime() + (parseInt(days) || 30) * 24 * 60 * 60 * 1000);
    user.isActive = true;
    await user.save();

    res.json({ message: `Подписка для ${user.username} продлена на ${days} дн.!`, user });
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

// Назначение / снятие админа (toggle-admin)
app.post('/api/admin/toggle-admin', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    user.isAdmin = !user.isAdmin;
    await user.save();

    res.json({ message: `Права администратора для ${user.username}: ${user.isAdmin ? 'ВКЛЮЧЕНЫ 👑' : 'ОТКЛЮЧЕНЫ'}`, user });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка смены прав администратора' });
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

// -------------------------------------------------------------
// ПАНЕЛЬ АДМИНИСТРАТОРА: СЕРВЕРЫ (VLESS REALITY КЛЮЧИ)
// -------------------------------------------------------------

// Список всех серверов для админа
app.get('/api/admin/servers', requireAdmin, async (req, res) => {
  try {
    const servers = await ServerModel.find().sort({ createdAt: 1 });
    res.json(servers);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка загрузки серверов' });
  }
});

// Добавление нового сервера (через vless:// или поля)
app.post('/api/admin/servers', requireAdmin, async (req, res) => {
  try {
    let { name, flag, vlessUrl, address, port, uuid, publicKey, shortId, sni, flow, fingerprint } = req.body;

    if (vlessUrl) {
      const parsed = parseVlessUri(vlessUrl);
      if (!parsed) {
        return res.status(400).json({ error: 'Неверный формат VLESS URL. Ссылка должна начинаться с vless://' });
      }
      address = parsed.address;
      port = parsed.port;
      uuid = parsed.uuid;
      publicKey = parsed.publicKey;
      shortId = parsed.shortId || '';
      sni = parsed.sni || '';
      flow = parsed.flow || 'xtls-rprx-vision';
      fingerprint = parsed.fingerprint || 'chrome';
      if (!name && parsed.rawName) {
        name = parsed.rawName;
      }
    }

    if (!name || !address || !port || !uuid || !publicKey) {
      return res.status(400).json({ error: 'Заполните обязательные параметры: Название, Адрес, Порт, UUID и Публичный ключ (pbk)' });
    }

    const newServer = new ServerModel({
      name: name.trim(),
      flag: flag && flag.trim() ? flag.trim() : '🌐',
      address: address.trim(),
      port: parseInt(port),
      uuid: uuid.trim(),
      publicKey: publicKey.trim(),
      shortId: shortId ? shortId.trim() : '',
      sni: sni ? sni.trim() : '',
      flow: flow ? flow.trim() : 'xtls-rprx-vision',
      fingerprint: fingerprint ? fingerprint.trim() : 'chrome',
      isActive: true
    });

    await newServer.save();
    console.log(`[ADMIN] Добавлен новый сервер: ${newServer.name} (${newServer.address}:${newServer.port})`);
    res.status(201).json({ message: `Сервер ${newServer.name} успешно добавлен!`, server: newServer });
  } catch (error) {
    console.error('Ошибка добавления сервера:', error);
    res.status(500).json({ error: 'Ошибка сохранения сервера' });
  }
});

// Переключение активности сервера
app.post('/api/admin/servers/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const server = await ServerModel.findById(req.params.id);
    if (!server) return res.status(404).json({ error: 'Сервер не найден' });

    server.isActive = !server.isActive;
    await server.save();
    res.json({ message: `Сервер ${server.name}: ${server.isActive ? 'Включен' : 'Отключен'}`, server });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка переключения сервера' });
  }
});

// Удаление сервера
app.delete('/api/admin/servers/:id', requireAdmin, async (req, res) => {
  try {
    const server = await ServerModel.findByIdAndDelete(req.params.id);
    if (!server) return res.status(404).json({ error: 'Сервер не найден' });

    res.json({ message: `Сервер ${server.name} удален` });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка удаления сервера' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🌲 JuniperVPN Backend запущен на порту ${PORT}`);
});
