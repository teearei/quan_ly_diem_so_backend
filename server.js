const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Để hash mật khẩu
const jwt = require('jsonwebtoken'); // Để tạo token xác thực
const fs = require('fs'); // Để đọc/ghi file JSON làm database

// --- Hàm tiện ích đọc/ghi dữ liệu (đặt ở đây) ---
function readUsersFromFile() {
    if (!fs.existsSync(DATA_FILE)) {
        // Tạo file nếu nó không tồn tại
        fs.writeFileSync(DATA_FILE, JSON.stringify({}));
        return {};
    }
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
}

function writeUsersToFile(users) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf8');
}

const app = express();
const PORT = 3000; // Cổng cho backend server

const SECRET_KEY = 'super_secret_key'; // Khóa bí mật để ký JWT, thay đổi nó trong thực tế!

// Cấu hình middleware
app.use(cors()); // Cho phép mọi domain truy cập (trong môi trường dev)
app.use(bodyParser.json()); // Xử lý body request dưới dạng JSON

// --- Giả lập Cơ sở dữ liệu bằng file JSON ---
// File sẽ lưu trữ thông tin người dùng và dữ liệu của họ
const DB_FILE = 'database.json';

// Hàm đọc dữ liệu từ file
function readDb() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }, null, 2));
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

// Hàm ghi dữ liệu vào file
function writeDb(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// --- Middleware xác thực JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // Không có token

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Token không hợp lệ hoặc hết hạn
        req.user = user; // Lưu thông tin người dùng vào request
        next();
    });
}

// --- Routes (API Endpoints) ---

// 1. Đăng ký tài khoản
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const db = readDb();

    if (db.users[username]) {
        return res.status(400).json({ message: 'Tên đăng nhập đã tồn tại!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash mật khẩu
    db.users[username] = {
        password: hashedPassword,
        students: [] // Dữ liệu sinh viên riêng cho mỗi người dùng
    };
    writeDb(db);
    res.status(201).json({ message: 'Đăng ký thành công!' });
});

// 2. Đăng nhập tài khoản
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const db = readDb();
    const user = db.users[username];

    if (!user) {
        return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    // Tạo JWT token
    const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Đăng nhập thành công!', token: accessToken, username: user.username });
});

// --- Các API cần xác thực (yêu cầu token) ---

// 3. Lấy danh sách sinh viên của người dùng hiện tại
app.get('/api/users/students', authenticateToken, (req, res) => {
    const userId = req.user.id; // Lấy ID người dùng từ token
    const user = readUsersFromFile()[userId];
    if (user) {
        // Đảm bảo user.students là một mảng, nếu không thì trả về mảng rỗng
        res.json(user.students || []);
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});

// 4. Thêm sinh viên mới
app.post('/api/students', authenticateToken, (req, res) => {
    const { name } = req.body;
    const db = readDb();
    const user = db.users[req.user.username];

    if (!user) {
        return res.status(404).json({ message: 'Người dùng không tìm thấy' });
    }

    const newStudent = {
        id: Date.now(),
        name: name,
        scores: {
            diemTX1: undefined, diemTX2: undefined, diemTX3: undefined, diemTX4: undefined,
            diemGK: undefined, diemCK: undefined
        }
    };
    user.students.push(newStudent);
    writeDb(db);
    res.status(201).json(newStudent);
});

// 5. Cập nhật điểm của một sinh viên
app.put('/api/students/:id', authenticateToken, (req, res) => {
    const studentId = parseInt(req.params.id);
    const updatedScores = req.body.scores; // Chỉ gửi các điểm cần cập nhật
    const db = readDb();
    const user = db.users[req.user.username];

    if (!user) {
        return res.status(404).json({ message: 'Người dùng không tìm thấy' });
    }

    const studentIndex = user.students.findIndex(s => s.id === studentId);

    if (studentIndex === -1) {
        return res.status(404).json({ message: 'Sinh viên không tìm thấy' });
    }

    // Cập nhật điểm
    user.students[studentIndex].scores = {
        ...user.students[studentIndex].scores, // Giữ lại điểm cũ nếu không gửi lên
        ...updatedScores // Ghi đè bằng điểm mới
    };
    writeDb(db);
    res.json(user.students[studentIndex]);
});

// 6. Xóa sinh viên
app.delete('/api/students/:id', authenticateToken, (req, res) => {
    const studentId = parseInt(req.params.id);
    const db = readDb();
    const user = db.users[req.user.username];

    if (!user) {
        return res.status(404).json({ message: 'Người dùng không tìm thấy' });
    }

    const initialLength = user.students.length;
    user.students = user.students.filter(s => s.id !== studentId);

    if (user.students.length === initialLength) {
        return res.status(404).json({ message: 'Sinh viên không tìm thấy' });
    }

    writeDb(db);
    res.status(200).json({ message: 'Sinh viên đã được xóa.' });
});


// Khởi động server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
