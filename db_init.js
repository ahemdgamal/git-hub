// الخادم الرئيسي (Express) مع مصادقة بسيطة وجلسات
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./store.db');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'replace_this_with_a_strong_secret',
  resave: false,
  saveUninitialized: false
}));

// Middleware: وضع رسائل في session للعرض مرة واحدة
app.use((req, res, next) => {
  res.locals.message = req.session.message || null;
  delete req.session.message;
  res.locals.user = req.session.user || null;
  next();
});

// Middleware للحماية: يلزم تسجيل الدخول للوصول إلى صفحات المتجر
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  req.session.message = { type: 'error', text: 'يجب تسجيل الدخول أو إنشاء حساب للوصول إلى الموقع.' };
  return res.redirect('/login');
}

// صفحة الدخول
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      console.error(err);
      req.session.message = { type: 'error', text: 'حدث خطأ، حاول مرة أخرى.' };
      return res.redirect('/login');
    }
    if (!user) {
      req.session.message = { type: 'error', text: 'لا يوجد حساب بهذا البريد. الرجاء إنشاء حساب جديد أولاً.' };
      return res.redirect('/login');
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      req.session.message = { type: 'error', text: 'كلمة المرور غير صحيحة.' };
      return res.redirect('/login');
    }
    // تسجيل الدخول ناجح: زيادة عداد الدخول وتخزين الجلسة
    db.run(`UPDATE users SET login_count = login_count + 1 WHERE id = ?`, [user.id]);
    req.session.user = { id: user.id, email: user.email, phone: user.phone };
    req.session.message = { type: 'success', text: 'تم تسجيل الدخول بنجاح.' };
    return res.redirect('/');
  });
});

// صفحة التسجيل
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { email, password, phone } = req.body;
  if (!email || !password) {
    req.session.message = { type: 'error', text: 'الرجاء إدخال البريد وكلمة المرور.' };
    return res.redirect('/register');
  }
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (email, password_hash, phone) VALUES (?, ?, ?)`, [email, hash, phone || ''], function (err) {
    if (err) {
      console.error(err);
      req.session.message = { type: 'error', text: 'يوجد حساب مسجل بهذا البريد بالفعل.' };
      return res.redirect('/register');
    }
    req.session.message = { type: 'success', text: 'تم إنشاء الحساب. يمكنك الآن تسجيل الدخول.' };
    return res.redirect('/login');
  });
});

// صفحة نسيت كلمة المرور (بسيطة)
app.get('/forgot', (req, res) => {
  res.render('forgot');
});

app.post('/forgot', (req, res) => {
  const { email } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error(err);
      req.session.message = { type: 'error', text: 'حدث خطأ.' };
      return res.redirect('/forgot');
    }
    if (!user) {
      req.session.message = { type: 'error', text: 'لا يوجد حساب بهذا البريد.' };
      return res.redirect('/forgot');
    }
    // هنا نُحاكي إرسال رابط إعادة تعيين كلمة المرور
    req.session.message = { type: 'success', text: 'تم إرسال تعليمات إعادة تعيين كلمة المرور إلى بريدك (محاكاة).' };
    return res.redirect('/login');
  });
});

// الخروج
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// الصفحة الرئيسية (محمية)
app.get('/', requireAuth, (req, res) => {
  res.render('home', { storeName: 'Ahemd gamal store' });
});

// صفحة من نحن (محمية حسب طلبك)
app.get('/about', requireAuth, (req, res) => {
  res.render('about', {
    creator: 'Ahemd gamal',
    email: 'ahemdgamal95@gmail.com',
    phone: '01554547362'
  });
});

// صفحة المنتجات - عرض الفئات
app.get('/products', requireAuth, (req, res) => {
  db.all(`SELECT DISTINCT category FROM products`, [], (err, rows) => {
    if (err) {
      console.error(err);
      rows = [];
    }
    const categories = rows.map(r => r.category);
    res.render('products', { categories });
  });
});

// صفحة كل فئة
app.get('/products/:category', requireAuth, (req, res) => {
  const cat = req.params.category;
  db.all(`SELECT * FROM products WHERE category = ?`, [cat], (err, products) => {
    if (err) {
      console.error(err);
      products = [];
    }
    res.render('category', { category: cat, products });
  });
});

// بدء الخادم
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
