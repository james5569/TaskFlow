const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    secret: 'taskflow_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
// If no DATABASE_URL is provided, it uses a default local postgres connection string
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres@localhost:5432/postgres'
});

// Create tables
const initDB = async () => {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(255) NOT NULL,
            last_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            department VARCHAR(255),
            phone VARCHAR(50),
            line_id VARCHAR(100),
            chat_app VARCHAR(100),
            preferred_contact VARCHAR(50),
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        await pool.query(`CREATE TABLE IF NOT EXISTS tasks (
            id VARCHAR(50) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            assign_to VARCHAR(50),
            assign_date VARCHAR(50),
            due_date VARCHAR(50),
            status VARCHAR(50) DEFAULT 'todo',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        await pool.query(`CREATE TABLE IF NOT EXISTS task_updates (
            id VARCHAR(50) PRIMARY KEY,
            task_id VARCHAR(50) REFERENCES tasks(id) ON DELETE CASCADE,
            update_date VARCHAR(50),
            detail TEXT,
            updated_by INT REFERENCES users(id) ON DELETE SET NULL,
            new_status VARCHAR(50)
        )`);

        // Seed an admin user if not exists
        const res = await pool.query(`SELECT * FROM users WHERE email = $1`, ['admin@taskflow.com']);
        if (res.rows.length === 0) {
            const rawPassword = 'password';
            const hash = await bcrypt.hash(rawPassword, 10);
            await pool.query(
                `INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
                ['Admin', 'User', 'admin@taskflow.com', hash, 'admin']
            );
        }
        console.log('Connected to PostgreSQL and verified tables.');
    } catch (err) {
        console.error('Error initializing database', err);
    }
};

initDB();

// --- AUTHENTICATION ENDPOINTS ---

app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, department, password, phone, lineId, chatApp, preferredContact } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (first_name, last_name, email, department, password_hash, phone, line_id, chat_app, preferred_contact) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [firstName, lastName, email, department, hash, phone, lineId, chatApp, preferredContact]
        );
        res.json({ message: 'สมัครสมาชิกสำเร็จ', id: result.rows[0].id });
    } catch (e) {
        if (e.code === '23505') { // postgres unique violation
            return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        }
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            req.session.userId = user.id;
            req.session.role = user.role;
            // Return full user info except password
            const { password_hash, ...userInfo } = user;
            res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: userInfo });
        } else {
            res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'ออกจากระบบสำเร็จ' });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const result = await pool.query(
            'SELECT id, first_name, last_name, email, department, role, phone, line_id, chat_app, preferred_contact FROM users WHERE id = $1',
            [req.session.userId]
        );
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/users', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    if (req.session.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    try {
        const result = await pool.query('SELECT id, first_name, last_name, email, department, phone, line_id, chat_app, preferred_contact, role FROM users');
        res.json({ users: result.rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/users/me', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

    const { firstName, lastName, email, department, phone, lineId, chatApp, preferredContact, password } = req.body;

    let query = `UPDATE users SET first_name=$1, last_name=$2, email=$3, department=$4, phone=$5, line_id=$6, chat_app=$7, preferred_contact=$8`;
    let params = [firstName, lastName, email, department, phone, lineId, chatApp, preferredContact];
    let paramIndex = 9;

    if (password && password.trim() !== '') {
        try {
            const hash = await bcrypt.hash(password, 10);
            query += `, password_hash=$${paramIndex++}`;
            params.push(hash);
        } catch (e) {
            return res.status(500).json({ error: 'Error hashing password' });
        }
    }

    query += ` WHERE id=$${paramIndex}`;
    params.push(req.session.userId);

    try {
        await pool.query(query, params);
        res.json({ message: 'อัปเดตข้อมูลสำเร็จ' });
    } catch (e) {
        if (e.code === '23505') return res.status(400).json({ error: 'อีเมลซ้ำ' });
        console.error(e);
        res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
    }
});

// --- TASKS ENDPOINTS ---

app.get('/api/tasks', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const query = `
            SELECT t.*, u.first_name || ' ' || u.last_name as "assignToName" 
            FROM tasks t
            LEFT JOIN users u ON CAST(NULLIF(t.assign_to, '') AS INTEGER) = u.id
            ORDER BY t.created_at DESC
        `;
        const result = await pool.query(query);
        // Postgres returns camelCase differently if quoted, map back properly for the frontend if needed
        const tasks = result.rows.map(row => ({
            ...row,
            assignToName: row.assignToName // From the alias
        }));
        res.json({ tasks });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/tasks', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const countRes = await pool.query('SELECT COUNT(*) as count FROM tasks');
        // ParseInt necessary as COUNT returns a BigInt string in node-pg
        const newIdNumber = parseInt(countRes.rows[0].count, 10) + 1;
        const newId = 'TK-' + String(newIdNumber).padStart(3, '0');

        let { name, assignTo, assignDate, dueDate, status, description } = req.body;
        if (assignTo === '') assignTo = null;

        await pool.query(
            `INSERT INTO tasks (id, name, assign_to, assign_date, due_date, status, description) 
            VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [newId, name, assignTo, assignDate, dueDate, status, description]
        );
        res.json({ message: 'สร้างงานสำเร็จ', id: newId });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/tasks/:id/updates', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const taskId = req.params.id;

    try {
        const query = `
            SELECT u.*, us.first_name || ' ' || us.last_name as "byName" 
            FROM task_updates u
            LEFT JOIN users us ON u.updated_by = us.id
            WHERE u.task_id = $1
            ORDER BY u.update_date DESC
        `;
        const result = await pool.query(query, [taskId]);
        const updates = result.rows.map(row => ({
            ...row,
            byName: row.byName
        }));
        res.json({ updates });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/updates/latest', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const query = `
            SELECT tu.* 
            FROM task_updates tu
            INNER JOIN (
                SELECT task_id, MAX(update_date) as max_date 
                FROM task_updates GROUP BY task_id
            ) max_tu ON tu.task_id = max_tu.task_id AND tu.update_date = max_tu.max_date
        `;
        const result = await pool.query(query);
        res.json({ updates: result.rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/tasks/:id/updates', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    const taskId = req.params.id;

    try {
        const countRes = await pool.query('SELECT COUNT(*) as count FROM task_updates');
        const newUpIdNumber = parseInt(countRes.rows[0].count, 10) + 1;
        const newUpId = 'UP-' + String(newUpIdNumber).padStart(3, '0');

        const { date, detail, newStatus } = req.body;

        await pool.query('BEGIN'); // Start transaction

        await pool.query(
            `INSERT INTO task_updates (id, task_id, update_date, detail, updated_by, new_status) 
            VALUES ($1, $2, $3, $4, $5, $6)`,
            [newUpId, taskId, date, detail, req.session.userId, newStatus]
        );

        if (newStatus) {
            await pool.query('UPDATE tasks SET status = $1 WHERE id = $2', [newStatus, taskId]);
        }

        await pool.query('COMMIT'); // Commit transaction

        res.json({ message: 'อัปเดตงานสำเร็จ', id: newUpId });
    } catch (e) {
        await pool.query('ROLLBACK'); // Rollback on error
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// App listen
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
