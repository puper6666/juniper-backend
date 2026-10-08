const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://kavyn522_db_user:<db_password>@cluster0.ambn0af.mongodb.net/juniper_vpn?retryWrites=true&w=majority&appName=Cluster0';

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  subscriptionExpiresAt: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  notes: { type: String, default: 'Master Account' },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date }
});

const User = mongoose.model('User', UserSchema);

async function createMasterUser() {
  try {
    console.log('Подключение к MongoDB...');
    await mongoose.connect(MONGO_URI);
    console.log('✅ Подключено к базе данных');

    const username = 'kavyn';
    const passwordRaw = 'puper666';
    const hashedPassword = await bcrypt.hash(passwordRaw, 10);

    // Подписка на 5 лет вперед (активна до 2031 года)
    const expiry = new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000);

    let user = await User.findOne({ username: 'kavyn' });
    if (user) {
      user.password = hashedPassword;
      user.subscriptionExpiresAt = expiry;
      user.isActive = true;
      await user.save();
      console.log(`✅ Пользователь ${username} успешно обновлен! Подписка активна на 5 лет.`);
    } else {
      user = new User({
        username: 'kavyn',
        password: hashedPassword,
        subscriptionExpiresAt: expiry,
        isActive: true,
        notes: 'Master user'
      });
      await user.save();
      console.log(`✅ Пользователь ${username} успешно создан! Подписка активна на 5 лет.`);
    }

    process.exit(0);
  } catch (err) {
    console.error('❌ Ошибка:', err.message);
    process.exit(1);
  }
}

createMasterUser();
