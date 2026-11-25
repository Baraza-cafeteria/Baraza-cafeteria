const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const backendDir = __dirname;
const webDir = path.resolve(backendDir, "..");
const db = new Database(path.join(backendDir, "baraza.db"));

app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
  CREATE TABLE IF NOT EXISTS menu (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL CHECK(price >= 0),
    category TEXT NOT NULL,
    image TEXT,
    stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    registration_number TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    photo_data TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
    student_id INTEGER,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    student_name TEXT NOT NULL,
    registration_number TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    menu_item_id INTEGER,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    quantity INTEGER NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_orders_student
    ON orders(registration_number, created_at);

  CREATE INDEX IF NOT EXISTS idx_items_order
    ON order_items(order_id);
`);

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

// Import existing JSON menu data once into SQLite.
const menuCount = db.prepare("SELECT COUNT(*) AS count FROM menu").get().count;

if (menuCount === 0) {
  const oldMenu = loadJson(path.join(backendDir, "menu.json"), []);

  const insertMenu = db.prepare(`
    INSERT OR IGNORE INTO menu
      (id, name, price, category, image, stock, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const importMenu = db.transaction(items => {
    for (const item of items) {
      if (!item || !item.name || !Number.isFinite(Number(item.price))) {
        continue;
      }

      insertMenu.run(
        Number(item.id) || Date.now() + Math.floor(Math.random() * 100000),
        String(item.name),
        Number(item.price),
        String(item.category || "Other"),
        item.image || null,
        Number.isInteger(Number(item.stock))
          ? Math.max(0, Number(item.stock))
          : 0,
        new Date().toISOString()
      );
    }
  });

  importMenu(Array.isArray(oldMenu) ? oldMenu : []);
}

// Import existing JSON orders once into SQLite.
const orderCount = db.prepare("SELECT COUNT(*) AS count FROM orders").get().count;

if (orderCount === 0) {
  const oldOrders = loadJson(path.join(backendDir, "orders.json"), []);

  const insertOrder = db.prepare(`
    INSERT INTO orders
      (student_name, registration_number, total, status, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertItem = db.prepare(`
    INSERT INTO order_items
      (order_id, menu_item_id, name, price, quantity)
    VALUES (?, ?, ?, ?, ?)
  `);

  const importOrders = db.transaction(items => {
    for (const order of items) {
      if (!order) continue;

      const registrationNumber = String(
        order.registrationNumber || ""
      ).trim().toUpperCase();

      const studentName = String(order.studentName || "Student");

      const result = insertOrder.run(
        studentName,
        registrationNumber,
        Number(order.total) || 0,
        String(order.status || "Pending"),
        order.createdAt || new Date().toISOString()
      );

      for (const item of Array.isArray(order.items) ? order.items : []) {
        insertItem.run(
          result.lastInsertRowid,
          item.menuItemId || item.id || null,
          String(item.name || "Menu item"),
          Number(item.price) || 0,
          Math.max(1, Number(item.quantity) || 1)
        );
      }
    }
  });

  importOrders(Array.isArray(oldOrders) ? oldOrders : []);
}

function normalizedRegistration(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, "")
    .toUpperCase();
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function safeEqualHex(first, second) {
  if (!first || !second || first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(first, "hex"),
    Buffer.from(second, "hex")
  );
}

function setSessionCookie(res, token, remember = false) {
  const maxAge = remember ? "; Max-Age=2592000" : "";
  res.setHeader(
    "Set-Cookie",
    `baraza_session=${token}; HttpOnly; SameSite=Strict; Path=/${maxAge}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "baraza_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
  );
}

function getCookie(req, name) {
  const rawCookie = req.headers.cookie || "";
  const cookie = rawCookie
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(name + "="));

  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
}

function createSession(role, studentId = null, remember = false) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const duration = remember
    ? 30 * 24 * 60 * 60 * 1000
    : 12 * 60 * 60 * 1000;

  const expiresAt = Date.now() + duration;

  db.prepare(`
    INSERT INTO sessions (token_hash, role, student_id, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(tokenHash, role, studentId, expiresAt);

  return token;
}

function authenticate(role) {
  return (req, res, next) => {
    const token = getCookie(req, "baraza_session");

    if (!token) {
      return res.status(401).json({ message: "Please sign in first." });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const session = db.prepare(`
      SELECT * FROM sessions
      WHERE token_hash = ? AND expires_at > ?
    `).get(tokenHash, Date.now());

    if (!session || session.role !== role) {
      return res.status(401).json({
        message: "Your session has expired. Please sign in again."
      });
    }

    req.session = session;

    if (role === "student") {
      req.student = db.prepare(`
        SELECT id, name, registration_number, photo_data
        FROM students
        WHERE id = ?
      `).get(session.student_id);

      if (!req.student) {
        return res.status(401).json({ message: "Student account not found." });
      }
    }

    next();
  };
}

const requireStudent = authenticate("student");
const requireAdmin = authenticate("admin");

function cleanStudent(student) {
  return {
    id: student.id,
    name: student.name,
    registrationNumber: student.registration_number,
    photo: student.photo_data || null
  };
}

function getOrder(orderId) {
  const order = db.prepare(`
    SELECT * FROM orders WHERE id = ?
  `).get(orderId);

  if (!order) return null;

  const items = db.prepare(`
    SELECT
      menu_item_id AS menuItemId,
      name,
      price,
      quantity
    FROM order_items
    WHERE order_id = ?
  `).all(orderId);

  return {
    id: order.id,
    studentName: order.student_name,
    registrationNumber: order.registration_number,
    total: order.total,
    status: order.status,
    createdAt: order.created_at,
    items
  };
}

// Serve website pages without exposing backend data files.
app.get(["/", "/index.html"], (req, res) => {
  res.sendFile(path.join(webDir, "index.html"));
});

app.get("/menu.html", (req, res) => {
  res.sendFile(path.join(webDir, "menu.html"));
});

app.get("/student.html", (req, res) => {
  res.sendFile(path.join(webDir, "student.html"));
});

app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(webDir, "admin.html"));
});

app.use(
  "/images",
  express.static(path.join(webDir, "images"), { fallthrough: false })
);

// Public menu. Stock is visible so the page can show available portions.
app.get("/api/menu", (req, res) => {
  const menu = db.prepare(`
    SELECT id, name, price, category, image, stock
    FROM menu
    ORDER BY category, name
  `).all();

  res.json(menu);
});

// Create student account.
app.post("/api/auth/register", (req, res) => {
  const name = String(req.body.name || "").trim();
  const registrationNumber =
    normalizedRegistration(req.body.registrationNumber);
  const password = String(req.body.password || "");

  if (
    name.length < 2 ||
    name.length > 100 ||
    registrationNumber.length < 3 ||
    registrationNumber.length > 40 ||
    password.length < 8
  ) {
    return res.status(400).json({
      message: "Enter your name, registration number, and a password of at least 8 characters."
    });
  }

  const existing = db.prepare(`
    SELECT id FROM students WHERE registration_number = ?
  `).get(registrationNumber);

  if (existing) {
    return res.status(409).json({
      message: "An account already exists for that registration number. Sign in instead."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const result = db.prepare(`
    INSERT INTO students
      (name, registration_number, password_salt, password_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    name,
    registrationNumber,
    salt,
    hashPassword(password, salt),
    new Date().toISOString()
  );

  const remember = req.body.rememberMe === true;
  const token = createSession("student", result.lastInsertRowid, remember);
  setSessionCookie(res, token, remember);

  const student = db.prepare(`
    SELECT id, name, registration_number, photo_data
    FROM students
    WHERE id = ?
  `).get(result.lastInsertRowid);

  res.status(201).json({ student: cleanStudent(student) });
});

// Sign in student.
app.post("/api/auth/login", (req, res) => {
  const registrationNumber =
    normalizedRegistration(req.body.registrationNumber);
  const password = String(req.body.password || "");

  const student = db.prepare(`
    SELECT * FROM students WHERE registration_number = ?
  `).get(registrationNumber);

  if (
    !student ||
    !safeEqualHex(
      hashPassword(password, student.password_salt),
      student.password_hash
    )
  ) {
    return res.status(401).json({
      message: "Registration number or password is incorrect."
    });
  }

  const remember = req.body.rememberMe === true;
  const token = createSession("student", student.id, remember);
  setSessionCookie(res, token, remember);

  res.json({ student: cleanStudent(student) });
});

// Sign out student.
app.post("/api/auth/logout", (req, res) => {
  const token = getCookie(req, "baraza_session");

  if (token) {
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    db.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .run(tokenHash);
  }

  clearSessionCookie(res);
  res.json({ message: "Signed out." });
});

// Student profile.
app.get("/api/student/profile", requireStudent, (req, res) => {
  res.json({ student: cleanStudent(req.student) });
});

app.patch("/api/student/profile", requireStudent, (req, res) => {
  const name = req.body.name === undefined
    ? req.student.name
    : String(req.body.name).trim();

  const photo = req.body.photo === undefined
    ? req.student.photo_data
    : req.body.photo;

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({
      message: "Name must be between 2 and 100 characters."
    });
  }

  if (
    photo !== null &&
    photo !== undefined &&
    (
      typeof photo !== "string" ||
      !/^data:image\/(jpeg|png|webp);base64,/.test(photo) ||
      photo.length > 1400000
    )
  ) {
    return res.status(400).json({
      message: "Choose a JPG, PNG, or WebP profile picture under 1 MB."
    });
  }

  db.prepare(`
    UPDATE students SET name = ?, photo_data = ? WHERE id = ?
  `).run(name, photo || null, req.student.id);

  const updated = db.prepare(`
    SELECT id, name, registration_number, photo_data
    FROM students
    WHERE id = ?
  `).get(req.student.id);

  res.json({ student: cleanStudent(updated) });
});

// Show this student's past orders, including imported orders
// that match their registration number.
app.get("/api/student/orders", requireStudent, (req, res) => {
  const orders = db.prepare(`
    SELECT id
    FROM orders
    WHERE registration_number = ?
    ORDER BY id DESC
  `).all(req.student.registration_number)
    .map(row => getOrder(row.id));

  res.json(orders);
});

// Place order. Stock check, stock reduction, and order save
// happen together in one SQLite transaction.
app.post("/api/orders", requireStudent, (req, res) => {
  const requestKey = String(req.get("Idempotency-Key") || "").slice(0, 100);
  const items = Array.isArray(req.body.items) ? req.body.items : [];

  if (!requestKey) {
    return res.status(400).json({
      message: "Order request key is missing. Please try again."
    });
  }

  if (!items.length) {
    return res.status(400).json({
      message: "Choose at least one food item."
    });
  }

  const quantities = new Map();

  for (const item of items) {
    const id = Number(item.id ?? item.menuItemId);
    const quantity = Number(item.quantity);

    if (
      !Number.isSafeInteger(id) ||
      !Number.isInteger(quantity) ||
      quantity < 1 ||
      quantity > 99
    ) {
      return res.status(400).json({
        message: "One of the item quantities is invalid."
      });
    }

    quantities.set(id, (quantities.get(id) || 0) + quantity);
  }

  const placeOrder = db.transaction(() => {
    const previous = db.prepare(`
      SELECT id, student_id
      FROM orders
      WHERE idempotency_key = ?
    `).get(requestKey);

    if (previous) {
      if (previous.student_id !== req.student.id) {
        throw Object.assign(new Error("Order key conflict."), { status: 409 });
      }

      return {
        order: getOrder(previous.id),
        duplicate: true
      };
    }

    const orderLines = [];
    let total = 0;

    for (const [id, quantity] of quantities) {
      const food = db.prepare(`
        SELECT id, name, price, stock
        FROM menu
        WHERE id = ?
      `).get(id);

      if (!food) {
        throw Object.assign(
          new Error("A selected food item is no longer on the menu."),
          { status: 409 }
        );
      }

      if (food.stock < quantity) {
        throw Object.assign(
          new Error(`${food.name} has only ${food.stock} portion(s) left. Please change your quantity.`),
          { status: 409 }
        );
      }

      orderLines.push({ ...food, quantity });
      total += food.price * quantity;
    }

    const result = db.prepare(`
      INSERT INTO orders
        (student_id, student_name, registration_number, total,
         status, idempotency_key, created_at)
      VALUES (?, ?, ?, ?, 'Pending', ?, ?)
    `).run(
      req.student.id,
      req.student.name,
      req.student.registration_number,
      total,
      requestKey,
      new Date().toISOString()
    );

    const orderId = result.lastInsertRowid;

    const reduceStock = db.prepare(`
      UPDATE menu
      SET stock = stock - ?, updated_at = ?
      WHERE id = ? AND stock >= ?
    `);

    const addLine = db.prepare(`
      INSERT INTO order_items
        (order_id, menu_item_id, name, price, quantity)
      VALUES (?, ?, ?, ?, ?)
    `);

    for (const line of orderLines) {
      const update = reduceStock.run(
        line.quantity,
        new Date().toISOString(),
        line.id,
        line.quantity
      );

      if (update.changes !== 1) {
        throw Object.assign(
          new Error(`${line.name} just sold out. Please refresh the menu.`),
          { status: 409 }
        );
      }

      addLine.run(
        orderId,
        line.id,
        line.name,
        line.price,
        line.quantity
      );
    }

    return {
      order: getOrder(orderId),
      duplicate: false
    };
  });

  try {
    const result = placeOrder.immediate();

    res
      .status(result.duplicate ? 200 : 201)
      .json({
        message: "Order received successfully!",
        order: result.order
      });
  } catch (error) {
    res
      .status(error.status || 500)
      .json({
        message: error.status
          ? error.message
          : "Could not save this order."
      });
  }
});

// Admin sign in.
app.post("/api/admin/login", (req, res) => {
  const expectedPassword = process.env.BARAZA_ADMIN_PASSWORD || "";
  const submittedPassword = String(req.body.password || "");

  if (expectedPassword.length < 12) {
    return res.status(503).json({
      message: "Set BARAZA_ADMIN_PASSWORD in the terminal before starting the server. Use at least 12 characters."
    });
  }

  const submittedHash = crypto
    .createHash("sha256")
    .update(submittedPassword)
    .digest("hex");

  const expectedHash = crypto
    .createHash("sha256")
    .update(expectedPassword)
    .digest("hex");

  if (!safeEqualHex(submittedHash, expectedHash)) {
    return res.status(401).json({
      message: "Admin password is incorrect."
    });
  }

  const token = createSession("admin");
  setSessionCookie(res, token);

  res.json({ message: "Admin signed in." });
});

// Admin menu and stock management.
app.get("/api/admin/menu", requireAdmin, (req, res) => {
  const menu = db.prepare(`
    SELECT id, name, price, category, image, stock
    FROM menu
    ORDER BY category, name
  `).all();

  res.json(menu);
});

app.patch("/api/admin/menu/:id/stock", requireAdmin, (req, res) => {
  const stock = Number(req.body.stock);

  if (!Number.isInteger(stock) || stock < 0 || stock > 100000) {
    return res.status(400).json({
      message: "Enter a whole number of portions from 0 to 100000."
    });
  }

  const result = db.prepare(`
    UPDATE menu
    SET stock = ?, updated_at = ?
    WHERE id = ?
  `).run(stock, new Date().toISOString(), Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ message: "Menu item not found." });
  }

  res.json({ message: "Available portions updated." });
});

// Admin order list and status updates.
app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT id FROM orders ORDER BY id DESC
  `).all().map(row => getOrder(row.id));

  res.json(orders);
});

app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const allowedStatuses = [
    "Pending",
    "Preparing",
    "Ready",
    "Completed",
    "Cancelled"
  ];

  if (!allowedStatuses.includes(req.body.status)) {
    return res.status(400).json({ message: "Invalid order status." });
  }

  const id = Number(req.params.id);
  const result = db.prepare(`
    UPDATE orders SET status = ? WHERE id = ?
  `).run(req.body.status, id);

  if (!result.changes) {
    return res.status(404).json({ message: "Order not found." });
  }

  res.json({
    message: "Order status updated.",
    order: getOrder(id)
  });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?")
    .run(req.session.token_hash);

  clearSessionCookie(res);
  res.json({ message: "Admin signed out." });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error.status === 404) {
    return res.status(404).send("Not found.");
  }

  console.error(error);
  res.status(500).json({ message: "The server encountered an error." });
});

app.listen(PORT, () => {
  console.log(`Baraza Cafeteria is running at http://localhost:${PORT}`);
  console.log("Menu stock defaults to 0. Sign in to Admin and set available portions before accepting orders.");
});