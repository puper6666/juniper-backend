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

// Схема версии приложения для OTA обновлений
const AppVersionSchema = new mongoose.Schema({
  versionCode: { type: Number, required: true, default: 1 },
  versionName: { type: String, required: true, default: '1.0.0' },
  apkUrl: { type: String, required: true, default: 'http://4.223.130.97/JuniperVPN.apk' },
  changelog: { type: String, default: 'Первый релиз JuniperVPN с поддержкой VLESS Reality' },
  isForceUpdate: { type: Boolean, default: false },
  updatedAt: { type: Date, default: Date.now }
});

const AppVersion = mongoose.model('AppVersion', AppVersionSchema);

// Схема учета устройств для предотвращения повторного использования триала
const TrialDeviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true, index: true },
  ip: { type: String, default: '' },
  registeredUsername: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const TrialDevice = mongoose.model('TrialDevice', TrialDeviceSchema);

// Вспомогательная функция автоопределения флага страны
function autoDetectFlag(name = '') {
  const n = (name || '').toLowerCase();
  if (n.includes('швеци') || n.includes('sweden') || n.includes('se')) return '🇸🇪';
  if (n.includes('польш') || n.includes('poland') || n.includes('pl')) return '🇵🇱';
  if (n.includes('росси') || n.includes('russia') || n.includes('ru') || n.includes('москв')) return '🇷🇺';
  if (n.includes('герман') || n.includes('germany') || n.includes('de') || n.includes('frankfurt') || n.includes('berlin')) return '🇩🇪';
  if (n.includes('нидерл') || n.includes('netherlands') || n.includes('nl') || n.includes('амстердам')) return '🇳🇱';
  if (n.includes('франц') || n.includes('france') || n.includes('fr') || n.includes('paris')) return '🇫🇷';
  if (n.includes('сша') || n.includes('usa') || n.includes('us') || n.includes('америк')) return '🇺🇸';
  if (n.includes('великобрит') || n.includes('uk') || n.includes('england') || n.includes('англия') || n.includes('london')) return '🇬🇧';
  if (n.includes('турци') || n.includes('turkey') || n.includes('tr') || n.includes('стамбул')) return '🇹🇷';
  if (n.includes('финлян') || n.includes('finland') || n.includes('fi') || n.includes('хельсинк')) return '🇫🇮';
  if (n.includes('казах') || n.includes('kazakhstan') || n.includes('kz')) return '🇰🇿';
  if (n.includes('япон') || n.includes('japan') || n.includes('jp') || n.includes('токио')) return '🇯🇵';
  if (n.includes('сингапур') || n.includes('singapore') || n.includes('sg')) return '🇸🇬';
  if (n.includes('оаэ') || n.includes('uae') || n.includes('dubai') || n.includes('дубай')) return '🇦🇪';
  if (n.includes('канад') || n.includes('canada') || n.includes('ca')) return '🇨🇦';
  if (n.includes('испан') || n.includes('spain') || n.includes('es') || n.includes('мадрид')) return '🇪🇸';
  if (n.includes('итали') || n.includes('italy') || n.includes('it') || n.includes('рим')) return '🇮🇹';
  if (n.includes('австри') || n.includes('austria') || n.includes('at') || n.includes('вена')) return '🇦🇹';
  if (n.includes('чехи') || n.includes('czech') || n.includes('cz') || n.includes('прага')) return '🇨🇿';
  return '🌐';
}

function parseVlessUri(uri) {
  try {
    const trimmed = (uri || '').trim().replace(/^["']|["']$/g, '');
    if (!trimmed.toLowerCase().startsWith('vless://')) return null;

    let uuid = '', address = '', port = 443, flow = '', sni = '', fingerprint = 'chrome', publicKey = '', shortId = '', rawName = '';

    // 1. Попробуем WHATWG URL
    try {
      const url = new URL(trimmed);
      uuid = url.username || '';
      address = url.hostname || '';
      port = parseInt(url.port) || 443;
      const params = url.searchParams;

      flow = params.get('flow') || '';
      sni = params.get('sni') || params.get('serverName') || params.get('host') || '';
      fingerprint = params.get('fp') || params.get('fingerprint') || 'chrome';
      publicKey = params.get('pbk') || params.get('pk') || params.get('publicKey') || params.get('public_key') || '';
      shortId = params.get('sid') || params.get('shortId') || params.get('short_id') || '';

      if (url.hash) {
        const hashStr = url.hash.substring(1);
        try {
          rawName = decodeURIComponent(hashStr);
        } catch (_) {
          rawName = hashStr;
        }
      }
    } catch (_) {
      // Игнорируем ошибку WHATWG URL и переходим к Regex
    }

    // 2. Резервный разбор через Regex (если WHATWG URL не смог или uuid пустой)
    if (!uuid || !address) {
      const regex = /^vless:\/\/([^@]+)@([^:/?#]+)(?::(\d+))?(?:\?([^#]*))?(?:#(.*))?$/i;
      const match = trimmed.match(regex);
      if (match) {
        uuid = match[1] || '';
        address = match[2] || '';
        port = parseInt(match[3]) || 443;

        const queryString = match[4] || '';
        const rawHash = match[5] || '';

        if (rawHash) {
          try {
            rawName = decodeURIComponent(rawHash);
          } catch (_) {
            rawName = rawHash;
          }
        }

        const queryParams = new URLSearchParams(queryString);
        flow = queryParams.get('flow') || flow || '';
        sni = queryParams.get('sni') || queryParams.get('serverName') || queryParams.get('host') || sni || '';
        fingerprint = queryParams.get('fp') || queryParams.get('fingerprint') || fingerprint || 'chrome';
        publicKey = queryParams.get('pbk') || queryParams.get('pk') || queryParams.get('publicKey') || queryParams.get('public_key') || publicKey || '';
        shortId = queryParams.get('sid') || queryParams.get('shortId') || queryParams.get('short_id') || shortId || '';
      }
    }

    if (!uuid || !address) return null;

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

// 1.1 Регистрация пробного периода на 24 часа (строго 1 раз на устройство)
app.post('/api/auth/register-trial', async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Укажите логин и пароль' });
    }
    const cleanUser = username.toLowerCase().trim();
    if (cleanUser.length < 3) {
      return res.status(400).json({ error: 'Логин должен быть не короче 3 символов' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: 'Пароль должен быть не короче 4 символов' });
    }

    // 1. Проверка идентификатора устройства (Device ID)
    const cleanDeviceId = (deviceId || '').trim();
    if (!cleanDeviceId || cleanDeviceId.length < 8) {
      return res.status(400).json({ error: 'Не передан уникальный идентификатор устройства. Обновите приложение.' });
    }

    const existingDevice = await TrialDevice.findOne({ deviceId: cleanDeviceId });
    if (existingDevice) {
      return res.status(403).json({
        error: '❌ На этом устройстве уже был использован бесплатный пробный период! Повторная активация невозможна. Оформите подписку для продолжения.'
      });
    }

    // 2. Лимит по IP-адресу (максимум 2 триала на один IP за 24 часа для защиты от эмуляторов)
    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
    if (clientIp && !clientIp.includes('127.0.0.1')) {
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const ipTrials = await TrialDevice.countDocuments({
        ip: clientIp,
        createdAt: { $gte: oneDayAgo }
      });
      if (ipTrials >= 3) {
        return res.status(429).json({
          error: '❌ С вашего IP-адреса превышен суточный лимит пробных периодов. Оформите подписку или попробуйте позже.'
        });
      }
    }

    const existing = await User.findOne({ username: cleanUser });
    if (existing) {
      return res.status(400).json({ error: 'Этот логин уже занят. Выберите другой.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 1); // 24 часа

    const newUser = new User({
      username: cleanUser,
      password: hashedPassword,
      subscriptionExpiresAt: expiry,
      isActive: true,
      isAdmin: false,
      notes: `Пробный период 24ч (Device: ${cleanDeviceId.substring(0, 12)}...)`
    });
    await newUser.save();

    // Фиксируем устройство в базе — повторно триал взять нельзя!
    const trialRecord = new TrialDevice({
      deviceId: cleanDeviceId,
      ip: clientIp,
      registeredUsername: cleanUser
    });
    await trialRecord.save();

    const token = jwt.sign(
      { id: newUser._id, username: newUser.username, isAdmin: false },
      process.env.JWT_SECRET || 'juniper_secret',
      { expiresIn: '60d' }
    );

    res.status(201).json({
      token,
      username: newUser.username,
      subscriptionExpiresAt: newUser.subscriptionExpiresAt,
      isSubActive: true,
      remainingDays: 1,
      isAdmin: false,
      message: '🎉 Пробный период на 24 часа активирован!'
    });
  } catch (e) {
    console.error('Ошибка регистрации триала:', e);
    res.status(500).json({ error: 'Ошибка активации пробного периода' });
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
    const isAdmin = Boolean(user.isAdmin || user.username === 'kavyn');
    if (!isAdmin && (!user.isActive || user.subscriptionExpiresAt <= now)) {
      return res.status(403).json({ error: 'Подписка истекла. Доступ к серверам ограничен.' });
    }

    const dbServers = await ServerModel.find({ isActive: true }).sort({ createdAt: 1 });
    if (dbServers && dbServers.length > 0) {
      const formatted = dbServers.map(s => ({
        id: s._id.toString(),
        name: s.name || 'Сервер',
        flag: s.flag || '🌐',
        address: s.address || '',
        port: s.port || 443,
        uuid: s.uuid || '',
        publicKey: s.publicKey || '',
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

// Создание пользователя (или продление существующего)
app.post('/api/admin/create-user', requireAdmin, async (req, res) => {
  try {
    const { username, password, days, isAdmin } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Укажите логин' });
    }

    const cleanUser = username.toLowerCase().trim();
    const subDays = parseInt(days) || 30;
    let existingUser = await User.findOne({ username: cleanUser });

    if (existingUser) {
      // Пользователь уже существует — продлеваем и обновляем пароль если передан
      if (password) {
        existingUser.password = await bcrypt.hash(password, 10);
      }
      const currentExpiry = existingUser.subscriptionExpiresAt > new Date() ? existingUser.subscriptionExpiresAt : new Date();
      existingUser.subscriptionExpiresAt = new Date(currentExpiry.getTime() + subDays * 24 * 60 * 60 * 1000);
      existingUser.isActive = true;
      if (isAdmin !== undefined) {
        existingUser.isAdmin = Boolean(isAdmin);
      }
      await existingUser.save();

      return res.status(200).json({
        message: `Пользователь ${existingUser.username} обновлен, подписка продлена на ${subDays} дн.!`,
        user: {
          _id: existingUser._id,
          username: existingUser.username,
          subscriptionExpiresAt: existingUser.subscriptionExpiresAt,
          isActive: existingUser.isActive,
          isAdmin: existingUser.isAdmin
        }
      });
    }

    if (!password) {
      return res.status(400).json({ error: 'Укажите пароль для нового пользователя' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const expiry = new Date(Date.now() + subDays * 24 * 60 * 60 * 1000);

    const user = new User({
      username: cleanUser,
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

// Продление подписки (по userId или по username)
app.post('/api/admin/extend', requireAdmin, async (req, res) => {
  try {
    const { userId, username, days } = req.body;
    let user = null;
    if (userId) {
      user = await User.findById(userId);
    } else if (username) {
      user = await User.findOne({ username: username.toLowerCase().trim() });
    }

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
    const formatted = servers.map(s => ({
      _id: s._id.toString(),
      id: s._id.toString(),
      name: s.name || 'Сервер',
      flag: s.flag || '🌐',
      address: s.address || '',
      port: s.port || 443,
      uuid: s.uuid || '',
      publicKey: s.publicKey || '',
      shortId: s.shortId || '',
      sni: s.sni || '',
      flow: s.flow || 'xtls-rprx-vision',
      fingerprint: s.fingerprint || 'chrome',
      isActive: Boolean(s.isActive),
      createdAt: s.createdAt ? s.createdAt.toISOString() : new Date().toISOString()
    }));
    res.json(formatted);
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
      if (parsed) {
        address = address || parsed.address;
        port = port || parsed.port;
        uuid = uuid || parsed.uuid;
        publicKey = publicKey || parsed.publicKey;
        shortId = shortId || parsed.shortId || '';
        sni = sni || parsed.sni || '';
        flow = flow !== undefined ? flow : (parsed.flow || '');
        fingerprint = fingerprint || parsed.fingerprint || 'chrome';
        if (!name && parsed.rawName) {
          name = parsed.rawName;
        }
      }
    }

    // Авто-дефолты для названия и адреса
    if (!name || !name.trim()) {
      if (address) {
        name = `Сервер ${address}:${port || 443}`;
      } else {
        name = 'Новый VPN Сервер';
      }
    }

    // Автоопределение флага по названию если не указан
    if (!flag || !flag.trim() || flag === '🌐') {
      flag = autoDetectFlag(name);
    }

    if (!address || !port || !uuid) {
      return res.status(400).json({ error: 'Не удалось определить адрес, порт или UUID из ссылки. Вставьте полную vless:// ссылку.' });
    }

    const newServer = new ServerModel({
      name: name.trim(),
      flag: flag && flag.trim() ? flag.trim() : '🌐',
      address: address.trim(),
      port: parseInt(port) || 443,
      uuid: uuid.trim(),
      publicKey: (publicKey || '').trim(),
      shortId: (shortId || '').trim(),
      sni: (sni || '').trim(),
      flow: (flow || '').trim(),
      fingerprint: (fingerprint || 'chrome').trim(),
      isActive: true
    });

    await newServer.save();
    console.log(`[ADMIN] Добавлен новый сервер: ${newServer.name} (${newServer.address}:${newServer.port})`);
    res.status(201).json({
      message: `Сервер ${newServer.name} успешно добавлен!`,
      server: {
        _id: newServer._id.toString(),
        id: newServer._id.toString(),
        name: newServer.name,
        flag: newServer.flag,
        address: newServer.address,
        port: newServer.port,
        uuid: newServer.uuid,
        publicKey: newServer.publicKey,
        shortId: newServer.shortId,
        sni: newServer.sni,
        flow: newServer.flow,
        fingerprint: newServer.fingerprint,
        isActive: newServer.isActive,
        createdAt: newServer.createdAt.toISOString()
      }
    });
  } catch (error) {
    console.error('Ошибка добавления сервера:', error);
    res.status(500).json({ error: 'Ошибка сохранения сервера: ' + (error.message || error) });
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

// -------------------------------------------------------------
// ПАНЕЛЬ АДМИНИСТРАТОРА: OTA ОБНОВЛЕНИЯ ПРИЛОЖЕНИЯ
// -------------------------------------------------------------

// Получение информации о последней версии приложения (публичный API)
app.get('/api/app-version', async (req, res) => {
  try {
    let latest = await AppVersion.findOne().sort({ updatedAt: -1 });
    if (!latest) {
      latest = await AppVersion.create({
        versionCode: 1,
        versionName: '1.0.0',
        apkUrl: 'http://4.223.130.97/JuniperVPN.apk',
        changelog: 'Первый релиз JuniperVPN с поддержкой VLESS Reality.',
        isForceUpdate: false
      });
    }
    res.json({
      versionCode: latest.versionCode,
      versionName: latest.versionName,
      apkUrl: latest.apkUrl,
      changelog: latest.changelog,
      isForceUpdate: Boolean(latest.isForceUpdate),
      updatedAt: latest.updatedAt
    });
  } catch (error) {
    console.error('Ошибка получения версии:', error);
    res.json({
      versionCode: 1,
      versionName: '1.0.0',
      apkUrl: 'http://4.223.130.97/JuniperVPN.apk',
      changelog: '',
      isForceUpdate: false
    });
  }
});

// Обновление версии администратором
app.post('/api/admin/app-version', requireAdmin, async (req, res) => {
  try {
    const { versionCode, versionName, apkUrl, changelog, isForceUpdate } = req.body;
    if (!versionCode || !versionName) {
      return res.status(400).json({ error: 'Укажите номер версии и код версии (versionCode)' });
    }

    let current = await AppVersion.findOne().sort({ updatedAt: -1 });
    if (!current) {
      current = new AppVersion();
    }

    current.versionCode = parseInt(versionCode) || 1;
    current.versionName = String(versionName).trim();
    if (apkUrl) current.apkUrl = String(apkUrl).trim();
    current.changelog = changelog !== undefined ? String(changelog) : current.changelog;
    current.isForceUpdate = Boolean(isForceUpdate);
    current.updatedAt = new Date();

    await current.save();

    console.log(`[ADMIN] Опубликована новая версия приложения: ${current.versionName} (${current.versionCode}), Force: ${current.isForceUpdate}`);
    res.json({
      message: `Версия ${current.versionName} успешно сохранена и опубликована!`,
      version: {
        versionCode: current.versionCode,
        versionName: current.versionName,
        apkUrl: current.apkUrl,
        changelog: current.changelog,
        isForceUpdate: current.isForceUpdate,
        updatedAt: current.updatedAt
      }
    });
  } catch (error) {
    console.error('Ошибка сохранения версии:', error);
    res.status(500).json({ error: 'Ошибка сохранения версии: ' + (error.message || error) });
  }
});

// Список использованных триалов для админки
app.get('/api/admin/trials', requireAdmin, async (req, res) => {
  try {
    const trials = await TrialDevice.find().sort({ createdAt: -1 }).limit(100);
    res.json(trials);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Сброс триала для устройства администратором (разрешить взять триал повторно)
app.post('/api/admin/trials/reset', requireAdmin, async (req, res) => {
  try {
    const { deviceId, username } = req.body;
    let query = {};
    if (deviceId) query.deviceId = deviceId.trim();
    else if (username) query.registeredUsername = username.trim().toLowerCase();
    else return res.status(400).json({ error: 'Укажите deviceId или username' });

    const result = await TrialDevice.deleteMany(query);
    res.json({ message: `Сброшено записей триала: ${result.deletedCount}` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🌲 JuniperVPN Backend запущен на порту ${PORT}`);
});
