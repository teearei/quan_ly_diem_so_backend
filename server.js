const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path'); // Đảm bảo bạn đã import path

// --- Biến môi trường và các biến cấu hình toàn cục ---
const PORT = process.env.PORT || 3000; // Sử dụng process.env.PORT cho Render
const SECRET_KEY = process.env.SECRET_KEY || 'super_secret_key'; // Lấy từ biến môi trường hoặc dùng mặc định
const DATA_FILE = path.join(__dirname, 'database.json'); // Đường dẫn đến file database, sử dụng path.join

// --- Hàm tiện ích đọc/ghi dữ liệu (chỉ dùng một cặp này) ---
function readDb() {
    if (!fs.existsSync(DATA_FILE)) {
        // Tạo file nếu nó không tồn tại với cấu trúc ban đầu
        fs.writeFileSync(DATA_FILE, JSON.stringify({ users: {} }, null, 2));
    }
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
}

function writeDb(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// --- Khởi tạo Express app ---
const app = express();

// --- Cấu hình middleware ---
app.use(cors()); // Cho phép mọi domain truy cập
app.use(bodyParser.json()); // Xử lý body request dưới dạng JSON

// --- Middleware xác thực JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log('No token provided');
        return res.sendStatus(401); // Không có token
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.sendStatus(403); // Token không hợp lệ hoặc hết hạn
        }
        req.user = user; // Lưu thông tin người dùng (chứa username) vào request
        next();
    });
}

// --- Routes (API Endpoints) ---

// 1. Đăng ký tài khoản
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const db = readDb(); // Dùng readDb

    if (db.users[username]) {
        return res.status(400).json({ message: 'Tên đăng nhập đã tồn tại!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.users[username] = {
        password: hashedPassword,
        students: [] // Dữ liệu sinh viên riêng cho mỗi người dùng
    };
    writeDb(db); // Dùng writeDb
    res.status(201).json({ message: 'Đăng ký thành công!' });
});

// 2. Đăng nhập tài khoản
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const db = readDb(); // Dùng readDb
    const user = db.users[username];

    if (!user) {
        return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    // Tạo JWT token (payload chỉ chứa username)
    const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Đăng nhập thành công!', token: accessToken, username: user.username });
});

// --- Các API cần xác thực (yêu cầu token) ---

// 3. Lấy danh sách sinh viên của người dùng hiện tại
app.get('/api/users/students', authenticateToken, (req, res) => {
    const db = readDb(); // Dùng readDb
    const usernameFromToken = req.user.username; // Lấy username từ token
    const user = db.users[usernameFromToken]; // Tìm người dùng bằng username

    if (user) {
        res.json(user.students || []); // Trả về mảng sinh viên hoặc mảng rỗng
    } else {
        // Rất hiếm khi xảy ra nếu token hợp lệ nhưng user lại không có trong DB
        res.status(404).json({ message: 'User not found' });
    }
});

// 4. Thêm sinh viên mới
app.post('/api/students', authenticateToken, (req, res) => {
    const { name } = req.body;
    const db = readDb(); // Dùng readDb
    const user = db.users[req.user.username]; // Lấy user bằng username từ token

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
    writeDb(db); // Dùng writeDb
    res.status(201).json(newStudent);
});

// 5. Cập nhật điểm của một sinh viên
app.put('/api/students/:id', authenticateToken, (req, res) => {
    const studentId = parseInt(req.params.id);
    const updatedScores = req.body.scores;
    const db = readDb(); // Dùng readDb
    const user = db.users[req.user.username]; // Lấy user bằng username từ token

    if (!user) {
        return res.status(404).json({ message: 'Người dùng không tìm thấy' });
    }

    const studentIndex = user.students.findIndex(s => s.id === studentId);

    if (studentIndex === -1) {
        return res.status(404).json({ message: 'Sinh viên không tìm thấy' });
    }

    user.students[studentIndex].scores = {
        ...user.students[studentIndex].scores,
        ...updatedScores
    };
    writeDb(db); // Dùng writeDb
    res.json(user.students[studentIndex]);
});

// 6. Xóa sinh viên
app.delete('/api/students/:id', authenticateToken, (req, res) => {
    const studentId = parseInt(req.params.id);
    const db = readDb(); // Dùng readDb
    const user = db.users[req.user.username]; // Lấy user bằng username từ token

    if (!user) {
        return res.status(404).json({ message: 'Người dùng không tìm thấy' });
    }

    const initialLength = user.students.length;
    user.students = user.students.filter(s => s.id !== studentId);

    if (user.students.length === initialLength) {
        return res.status(404).json({ message: 'Sinh viên không tìm thấy' });
    }

    writeDb(db); // Dùng writeDb
    res.status(200).json({ message: 'Sinh viên đã được xóa.' });
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});