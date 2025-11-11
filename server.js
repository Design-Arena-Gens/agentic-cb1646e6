const express = require('express');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');
const dayjs = require('dayjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.cwd();
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const VOUCHERS_FILE = path.join(DATA_DIR, 'vouchers.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const INVOICE_DIR = path.join(DATA_DIR, 'invoices');

for (const dir of [UPLOAD_DIR, INVOICE_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const ensureJsonFile = async (filePath) => {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
    const raw = await fsp.readFile(filePath, 'utf-8');
    if (!raw.trim()) {
      await fsp.writeFile(filePath, '[]');
    }
  } catch (err) {
    await fsp.writeFile(filePath, '[]');
  }
};

ensureJsonFile(ORDERS_FILE);
ensureJsonFile(VOUCHERS_FILE);

class JsonStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.queue = Promise.resolve();
  }

  async read() {
    const raw = await fsp.readFile(this.filePath, 'utf-8');
    if (!raw.trim()) return [];
    try {
      return JSON.parse(raw);
    } catch (error) {
      console.error(`Failed to parse JSON for ${this.filePath}`, error);
      throw error;
    }
  }

  async write(data) {
    await fsp.writeFile(this.filePath, JSON.stringify(data, null, 2));
  }

  async update(mutator) {
    this.queue = this.queue.then(async () => {
      const current = await this.read();
      const updated = await mutator(current);
      await this.write(updated);
      return updated;
    });
    return this.queue;
  }
}

const ordersStore = new JsonStore(ORDERS_FILE);
const vouchersStore = new JsonStore(VOUCHERS_FILE);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, unique);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'));
    }
  }
});

const transporter = (() => {
  if (process.env.SMTP_HOST) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      } : undefined
    });
  }
  return nodemailer.createTransport({ jsonTransport: true });
})();

const twilioClient = (() => {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (sid && token) {
    return twilio(sid, token);
  }
  return null;
})();

const otpStore = new Map();
const customerTokens = new Map();
const adminTokens = new Set();

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const validateEmail = (email) => /.+@.+\..+/.test(email);

const calculatePrice = ({ paperSize, colorMode, quantity, pageCount }) => {
  const baseRates = {
    A4: { color: 0.35, bw: 0.18 },
    A3: { color: 0.55, bw: 0.28 }
  };
  const sizeRates = baseRates[paperSize] || baseRates.A4;
  const rate = colorMode === 'color' ? sizeRates.color : sizeRates.bw;
  const pages = Math.max(pageCount || 1, 1);
  const subtotal = rate * pages * quantity;
  let discountRate = 0;
  if (quantity >= 50) discountRate = 0.2;
  else if (quantity >= 20) discountRate = 0.12;
  else if (quantity >= 10) discountRate = 0.05;
  const discount = parseFloat((subtotal * discountRate).toFixed(2));
  const total = parseFloat((subtotal - discount).toFixed(2));
  return { rate, subtotal: parseFloat(subtotal.toFixed(2)), discount, total };
};

const buildInvoice = (order) => {
  return new Promise((resolve, reject) => {
    const invoicePath = path.join(INVOICE_DIR, `${order.id}.pdf`);
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(invoicePath);
    doc.pipe(stream);

    doc.fontSize(20).text('Digital Print Pro - Invoice', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Invoice #: ${order.id}`);
    doc.text(`Date: ${dayjs(order.createdAt).format('DD MMM YYYY HH:mm')}`);
    doc.moveDown();

    doc.fontSize(14).text('Customer Details');
    doc.fontSize(12).text(`Name: ${order.customer.name}`);
    doc.text(`Email: ${order.customer.email}`);
    doc.text(`Mobile: ${order.customer.mobile}`);
    doc.moveDown();

    doc.fontSize(14).text('Order Summary');
    doc.fontSize(12).text(`Paper Size: ${order.print.paperSize}`);
    doc.text(`Color Mode: ${order.print.colorMode}`);
    doc.text(`Quantity: ${order.print.quantity}`);
    doc.text(`Pages: ${order.print.pageCount}`);
    doc.text(`Voucher: ${order.pricing.voucherCode || 'N/A'}`);
    doc.moveDown();

    doc.fontSize(14).text('Pricing');
    doc.fontSize(12).text(`Rate Per Page: $${order.pricing.rate.toFixed(2)}`);
    doc.text(`Subtotal: $${order.pricing.subtotal.toFixed(2)}`);
    doc.text(`Bulk Discount: $${order.pricing.discount.toFixed(2)}`);
    doc.text(`Voucher Discount: $${order.pricing.voucherDiscount.toFixed(2)}`);
    doc.text(`Total: $${order.pricing.total.toFixed(2)}`);

    doc.moveDown();
    doc.text('Thank you for choosing Digital Print Pro!', { align: 'center' });

    doc.end();
    stream.on('finish', () => resolve(invoicePath));
    stream.on('error', reject);
  });
};

const sendOrderEmail = async (order, invoicePath) => {
  const mailOptions = {
    from: process.env.MAIL_FROM || 'no-reply@digitalprintpro.local',
    to: order.customer.email,
    subject: `Digital Print Pro - Order Confirmation (${order.id})`,
    text: `Hi ${order.customer.name}, your order has been received. Total: $${order.pricing.total.toFixed(2)}.`,
    attachments: invoicePath ? [{ filename: `${order.id}.pdf`, path: invoicePath }] : []
  };
  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Email send failed', error.message);
  }
};

const sendWhatsAppAlert = async (order) => {
  if (!twilioClient) {
    console.warn('Twilio not configured, skipping WhatsApp alert.');
    return;
  }
  const from = process.env.TWILIO_WHATSAPP_FROM;
  const to = process.env.ADMIN_WHATSAPP_TO;
  if (!from || !to) {
    console.warn('Twilio WhatsApp endpoints missing.');
    return;
  }
  try {
    await twilioClient.messages.create({
      from,
      to,
      body: `New order ${order.id} from ${order.customer.name}. Total $${order.pricing.total}`
    });
  } catch (error) {
    console.error('WhatsApp alert failed', error.message);
  }
};

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(DATA_DIR, 'public')));

const requireAdmin = (req, res, next) => {
  const token = req.headers['x-admin-token'];
  if (!token || !adminTokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

const requireCustomer = (req, res, next) => {
  const token = req.headers['x-customer-token'];
  if (!token || !customerTokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.customerEmail = customerTokens.get(token);
  next();
};

app.post('/api/orders', upload.array('files', 3), async (req, res) => {
  try {
    const { name, email, mobile, paperSize, colorMode, quantity, pageCount, notes, voucherCode, eta } = req.body;
    if (!name || !validateEmail(email) || !mobile) {
      return res.status(400).json({ error: 'Invalid customer details' });
    }
    const qty = Number(quantity) || 1;
    const pages = Number(pageCount) || 1;
    const pricing = calculatePrice({ paperSize, colorMode, quantity: qty, pageCount: pages });

    let voucherDiscount = 0;
    let appliedVoucher = null;
    if (voucherCode) {
      await vouchersStore.update((list) => {
        const voucher = list.find((v) => v.code.toLowerCase() === voucherCode.toLowerCase() && v.active !== false);
        if (voucher) {
          if (!voucher.usageCount) voucher.usageCount = 0;
          if (voucher.usageLimit && voucher.usageCount >= voucher.usageLimit) {
            return list;
          }
          voucherDiscount = parseFloat((pricing.total * (voucher.discountPercent / 100)).toFixed(2));
          appliedVoucher = voucher;
          pricing.total = parseFloat((pricing.total - voucherDiscount).toFixed(2));
          voucher.usageCount += 1;
        }
        return list;
      });
    }

    const files = (req.files || []).map((file) => ({
      originalName: file.originalname,
      storedName: file.filename,
      path: file.path,
      mimetype: file.mimetype,
      size: file.size
    }));

    const order = {
      id: uuidv4(),
      createdAt: new Date().toISOString(),
      status: 'received',
      timeline: [
        {
          status: 'received',
          timestamp: new Date().toISOString(),
          note: 'Order received'
        }
      ],
      customer: { name, email, mobile },
      print: { paperSize, colorMode, quantity: qty, pageCount: pages, eta: eta || null, notes: notes || '' },
      files,
      pricing: {
        ...pricing,
        voucherDiscount,
        voucherCode: appliedVoucher ? appliedVoucher.code : voucherCode || null
      },
      queuePosition: null,
      chats: []
    };

    await ordersStore.update((orders) => {
      const queueOrders = orders.filter((o) => ['received', 'processing'].includes(o.status));
      order.queuePosition = queueOrders.length + 1;
      return [...orders, order];
    });

    const invoicePath = await buildInvoice(order);
    await sendOrderEmail(order, invoicePath);
    await sendWhatsAppAlert(order);

    res.json({
      order,
      invoiceUrl: `/api/orders/${order.id}/invoice`
    });
  } catch (error) {
    console.error('Order creation failed', error);
    res.status(500).json({ error: error.message || 'Failed to create order' });
  }
});

app.get('/api/orders/:id/invoice', async (req, res) => {
  const invoicePath = path.join(INVOICE_DIR, `${req.params.id}.pdf`);
  if (!fs.existsSync(invoicePath)) {
    return res.status(404).json({ error: 'Invoice not found' });
  }
  res.download(invoicePath);
});

app.post('/api/auth/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  const otp = generateOTP();
  otpStore.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });
  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM || 'no-reply@digitalprintpro.local',
      to: email,
      subject: 'Digital Print Pro Login OTP',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`
    });
  } catch (error) {
    console.error('OTP email failed', error.message);
  }
  res.json({ message: 'OTP sent if email is registered' });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!validateEmail(email) || !otp) {
    return res.status(400).json({ error: 'Invalid payload' });
  }
  const entry = otpStore.get(email);
  if (!entry || entry.otp !== otp || entry.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Invalid or expired OTP' });
  }
  otpStore.delete(email);
  const token = uuidv4();
  customerTokens.set(token, email);
  res.json({ token });
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password') {
    const token = uuidv4();
    adminTokens.add(token);
    setTimeout(() => adminTokens.delete(token), 12 * 60 * 60 * 1000);
    return res.json({ token });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/orders/customer', requireCustomer, async (req, res) => {
  const email = req.customerEmail;
  const orders = await ordersStore.read();
  const customerOrders = orders.filter((order) => order.customer.email === email);
  res.json({ orders: customerOrders });
});

app.get('/api/orders/track/:id', async (req, res) => {
  const orders = await ordersStore.read();
  const order = orders.find((o) => o.id === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  res.json({ order });
});

app.patch('/api/orders/:id/status', requireAdmin, async (req, res) => {
  const { status, note, eta } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Status required' });
  }
  let updatedOrder = null;
  await ordersStore.update((orders) => {
    return orders.map((order) => {
      if (order.id === req.params.id) {
        order.status = status;
        if (eta) order.print.eta = eta;
        order.timeline.push({ status, timestamp: new Date().toISOString(), note: note || '' });
        updatedOrder = order;
      }
      return order;
    });
  });
  if (!updatedOrder) {
    return res.status(404).json({ error: 'Order not found' });
  }
  res.json({ order: updatedOrder });
});

app.post('/api/orders/:id/chat', async (req, res) => {
  const { role, name, message } = req.body;
  if (!message || !role) {
    return res.status(400).json({ error: 'Message and role required' });
  }
  let updated = null;
  await ordersStore.update((orders) => {
    return orders.map((order) => {
      if (order.id === req.params.id) {
        const chatMessage = {
          id: uuidv4(),
          role,
          name: name || role,
          message,
          timestamp: new Date().toISOString()
        };
        order.chats = order.chats || [];
        order.chats.push(chatMessage);
        updated = chatMessage;
      }
      return order;
    });
  });
  if (!updated) {
    return res.status(404).json({ error: 'Order not found' });
  }
  res.json({ message: updated });
});

app.get('/api/orders/:id/chat', async (req, res) => {
  const orders = await ordersStore.read();
  const order = orders.find((o) => o.id === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  res.json({ chats: order.chats || [] });
});

app.post('/api/orders/:id/reorder', requireCustomer, async (req, res) => {
  const email = req.customerEmail;
  let newOrder = null;
  await ordersStore.update((orders) => {
    const original = orders.find((o) => o.id === req.params.id && o.customer.email === email);
    if (!original) {
      return orders;
    }
    const queueOrders = orders.filter((o) => ['received', 'processing'].includes(o.status)).length;
    newOrder = {
      ...original,
      id: uuidv4(),
      createdAt: new Date().toISOString(),
      status: 'received',
      timeline: [
        {
          status: 'received',
          timestamp: new Date().toISOString(),
          note: 'One-click reorder'
        }
      ],
      queuePosition: queueOrders + 1
    };
    return [...orders, newOrder];
  });
  if (!newOrder) {
    return res.status(404).json({ error: 'Order not found' });
  }
  const invoicePath = await buildInvoice(newOrder);
  await sendOrderEmail(newOrder, invoicePath);
  await sendWhatsAppAlert(newOrder);
  res.json({ order: newOrder, invoiceUrl: `/api/orders/${newOrder.id}/invoice` });
});

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const orders = await ordersStore.read();
  res.json({ orders });
});

app.post('/api/admin/vouchers', requireAdmin, async (req, res) => {
  const { code, discountPercent, usageLimit } = req.body;
  if (!code || !discountPercent) {
    return res.status(400).json({ error: 'Code and discount required' });
  }
  await vouchersStore.update((list) => {
    const exists = list.find((v) => v.code.toLowerCase() === code.toLowerCase());
    if (exists) {
      exists.discountPercent = Number(discountPercent);
      exists.usageLimit = usageLimit ? Number(usageLimit) : null;
      exists.active = true;
      return list;
    }
    return [
      ...list,
      {
        id: uuidv4(),
        code,
        discountPercent: Number(discountPercent),
        usageLimit: usageLimit ? Number(usageLimit) : null,
        usageCount: 0,
        active: true,
        createdAt: new Date().toISOString()
      }
    ];
  });
  res.json({ message: 'Voucher saved' });
});

app.post('/api/vouchers/redeem', async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Code required' });
  }
  const vouchers = await vouchersStore.read();
  const voucher = vouchers.find((v) => v.code.toLowerCase() === code.toLowerCase() && v.active !== false);
  if (!voucher) {
    return res.status(404).json({ error: 'Voucher not found' });
  }
  if (voucher.usageLimit && voucher.usageCount >= voucher.usageLimit) {
    return res.status(400).json({ error: 'Voucher fully redeemed' });
  }
  res.json({ voucher });
});

app.get('/api/queue', async (req, res) => {
  const orders = await ordersStore.read();
  const queue = orders
    .filter((order) => ['received', 'processing'].includes(order.status))
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map((order, idx) => ({
      id: order.id,
      name: order.customer.name,
      status: order.status,
      eta: order.print.eta || null,
      submitted: order.createdAt,
      position: idx + 1
    }));
  res.json({ queue });
});

app.get('/api/stats/summary', requireAdmin, async (req, res) => {
  const orders = await ordersStore.read();
  const totalRevenue = orders.reduce((sum, order) => sum + (order.pricing?.total || 0), 0);
  const active = orders.filter((order) => ['received', 'processing'].includes(order.status)).length;
  const completed = orders.filter((order) => order.status === 'completed').length;
  const pendingInvoices = orders.filter((order) => !order.pricing).length;
  res.json({ totalRevenue, active, completed, pendingInvoices });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers['x-admin-token'];
  adminTokens.delete(token);
  res.json({ message: 'Logged out' });
});

app.post('/api/customer/logout', requireCustomer, (req, res) => {
  const token = req.headers['x-customer-token'];
  customerTokens.delete(token);
  res.json({ message: 'Logged out' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Digital Print Pro server running on port ${PORT}`);
  });
}

module.exports = app;
