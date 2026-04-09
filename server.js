const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const Stripe = require("stripe");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const DB_PATH = path.join(__dirname, "db.json");

const PLANS = {
  pro_0_5: { seatLimit: 5, name: "HospiceLink Pro 0-5" },
  pro_5_10: { seatLimit: 10, name: "HospiceLink Pro 5-10" },
  pro_10_20: { seatLimit: 20, name: "HospiceLink Pro 10-20" },
  pro_unlimited: { seatLimit: null, name: "HospiceLink Pro Unlimited" },
  gold_0_10: { seatLimit: 10, name: "HospiceLink Gold 0-10" },
  gold_10_20: { seatLimit: 20, name: "HospiceLink Gold 10-20" },
  gold_unlimited: { seatLimit: null, name: "HospiceLink Gold Unlimited" },
  max_0_10: { seatLimit: 10, name: "HospiceLink Max 0-10" },
  max_10_20: { seatLimit: 20, name: "HospiceLink Max 10-20" },
  max_unlimited: { seatLimit: null, name: "HospiceLink Max Unlimited" }
};

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ tenants: [], users: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function getTenantUserCount(db, tenantId) {
  return db.users.filter(u => u.tenantId === tenantId && u.isActive !== false).length;
}

function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ message: "Missing token." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token." });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "org_admin" && req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  next();
}

app.use(cors());
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("We Market Plus backend is running.");
});

app.post("/api/onboard-admin", async (req, res) => {
  const { companyName, email, username, password, planCode } = req.body;

  if (!companyName || !email || !username || !password || !planCode) {
    return res.status(400).json({ message: "Missing required fields." });
  }
  if (!PLANS[planCode]) {
    return res.status(400).json({ message: "Invalid plan code." });
  }

  const db = loadDB();

  let tenant = db.tenants.find(t => t.billingEmail.toLowerCase() === email.toLowerCase());

  if (!tenant) {
    tenant = {
      id: uuidv4(),
      companyName,
      billingEmail: email,
      planCode,
      seatLimit: PLANS[planCode].seatLimit,
      subscriptionStatus: "active",
      isSuspended: false,
      stripeCustomerId: null,
      stripeSubscriptionId: null,
      createdAt: new Date().toISOString()
    };
    db.tenants.push(tenant);
  } else {
    tenant.companyName = companyName;
    tenant.planCode = planCode;
    tenant.seatLimit = PLANS[planCode].seatLimit;
  }

  const existingUser = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (existingUser) {
    return res.status(400).json({ message: "Username already exists." });
  }

  const existingAdmin = db.users.find(u => u.tenantId === tenant.id && u.role === "org_admin");
  if (existingAdmin) {
    return res.status(400).json({ message: "Admin already exists for this account." });
  }

  const hash = await bcrypt.hash(password, 10);

  db.users.push({
    id: uuidv4(),
    tenantId: tenant.id,
    username,
    email,
    passwordHash: hash,
    role: "org_admin",
    isActive: true,
    createdAt: new Date().toISOString()
  });

  saveDB(db);
  return res.json({ message: "Admin account created.", tenantId: tenant.id });
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required." });

  const db = loadDB();
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ message: "Invalid credentials." });

  const tenant = db.tenants.find(t => t.id === user.tenantId);
  if (!tenant) return res.status(401).json({ message: "Tenant not found." });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials." });

  if (tenant.isSuspended || ["past_due", "unpaid", "canceled", "deleted"].includes((tenant.subscriptionStatus || "").toLowerCase())) {
    return res.status(403).json({ message: "CRM access suspended due to subscription status." });
  }

  const token = jwt.sign({
    userId: user.id,
    tenantId: tenant.id,
    role: user.role,
    username: user.username
  }, JWT_SECRET, { expiresIn: "12h" });

  return res.json({
    message: "Login successful.",
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      tenantId: tenant.id,
      companyName: tenant.companyName
    }
  });
});

app.get("/api/me", auth, (req, res) => {
  const db = loadDB();
  const tenant = db.tenants.find(t => t.id === req.user.tenantId);
  const users = db.users.filter(u => u.tenantId === req.user.tenantId);

  if (!tenant) return res.status(404).json({ message: "Tenant not found." });

  return res.json({
    tenant: {
      companyName: tenant.companyName,
      billingEmail: tenant.billingEmail,
      planCode: tenant.planCode,
      seatLimit: tenant.seatLimit,
      currentUserCount: users.filter(u => u.isActive !== false).length,
      subscriptionStatus: tenant.subscriptionStatus,
      isSuspended: tenant.isSuspended
    }
  });
});

app.get("/api/admin/users", auth, requireAdmin, (req, res) => {
  const db = loadDB();
  const users = db.users
    .filter(u => u.tenantId === req.user.tenantId)
    .map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      isActive: u.isActive !== false
    }));

  res.json({ users });
});

app.post("/api/admin/users", auth, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  const db = loadDB();

  const tenant = db.tenants.find(t => t.id === req.user.tenantId);
  if (!tenant) return res.status(404).json({ message: "Tenant not found." });

  if (tenant.isSuspended || ["past_due", "unpaid", "canceled", "deleted"].includes((tenant.subscriptionStatus || "").toLowerCase())) {
    return res.status(403).json({ message: "Cannot add users while subscription is suspended." });
  }

  const currentUserCount = getTenantUserCount(db, tenant.id);
  if (tenant.seatLimit !== null && currentUserCount >= tenant.seatLimit) {
    return res.status(400).json({ message: `Seat limit reached. This plan allows ${tenant.seatLimit} active users.` });
  }

  const duplicate = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (duplicate) return res.status(400).json({ message: "Username already exists." });

  const hash = await bcrypt.hash(password, 10);

  db.users.push({
    id: uuidv4(),
    tenantId: tenant.id,
    username,
    email,
    passwordHash: hash,
    role: role || "staff",
    isActive: true,
    createdAt: new Date().toISOString()
  });

  saveDB(db);
  res.json({ message: "User created successfully." });
});

app.post("/api/admin/change-username", auth, requireAdmin, (req, res) => {
  const { userId, newUsername } = req.body;
  const db = loadDB();

  const user = db.users.find(u => u.id === userId && u.tenantId === req.user.tenantId);
  if (!user) return res.status(404).json({ message: "User not found." });

  const duplicate = db.users.find(u => u.username.toLowerCase() === newUsername.toLowerCase() && u.id !== user.id);
  if (duplicate) return res.status(400).json({ message: "That username is already in use." });

  user.username = newUsername;
  saveDB(db);
  res.json({ message: "Username updated." });
});

app.post("/api/admin/reset-password", auth, requireAdmin, async (req, res) => {
  const { userId, newPassword } = req.body;
  const db = loadDB();

  const user = db.users.find(u => u.id === userId && u.tenantId === req.user.tenantId);
  if (!user) return res.status(404).json({ message: "User not found." });

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  saveDB(db);
  res.json({ message: "Password updated." });
});

app.post("/api/admin/set-suspension", auth, requireAdmin, (req, res) => {
  const { isSuspended } = req.body;
  const db = loadDB();

  const tenant = db.tenants.find(t => t.id === req.user.tenantId);
  if (!tenant) return res.status(404).json({ message: "Tenant not found." });

  tenant.isSuspended = !!isSuspended;
  saveDB(db);
  res.json({ message: "Suspension status updated.", isSuspended: tenant.isSuspended });
});

app.post("/webhook", bodyParser.raw({ type: "application/json" }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(400).send("Stripe not configured.");
  }

  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const db = loadDB();

  function findTenantByEmail(email) {
    if (!email) return null;
    return db.tenants.find(t => (t.billingEmail || "").toLowerCase() === email.toLowerCase());
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email || null;
    const tenant = findTenantByEmail(email);

    if (tenant) {
      tenant.subscriptionStatus = "active";
      tenant.isSuspended = false;
      tenant.stripeCustomerId = session.customer || tenant.stripeCustomerId || null;
      tenant.stripeSubscriptionId = session.subscription || tenant.stripeSubscriptionId || null;
      saveDB(db);
    }
  }

  if (event.type === "customer.subscription.updated") {
    const sub = event.data.object;
    const tenant = db.tenants.find(t =>
      t.stripeSubscriptionId === sub.id || t.stripeCustomerId === sub.customer
    );

    if (tenant) {
      tenant.subscriptionStatus = sub.status;
      tenant.isSuspended = !["active", "trialing"].includes((sub.status || "").toLowerCase());
      saveDB(db);
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object;
    const tenant = db.tenants.find(t =>
      t.stripeSubscriptionId === sub.id || t.stripeCustomerId === sub.customer
    );

    if (tenant) {
      tenant.subscriptionStatus = "deleted";
      tenant.isSuspended = true;
      saveDB(db);
    }
  }

  if (event.type === "invoice.payment_failed") {
    const invoice = event.data.object;
    const tenant = db.tenants.find(t => t.stripeCustomerId === invoice.customer);

    if (tenant) {
      tenant.subscriptionStatus = "past_due";
      tenant.isSuspended = true;
      saveDB(db);
    }
  }

  res.json({ received: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
