const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DEV_PASSWORD = process.env.DEV_PASSWORD || 'ELDER2026';
const DB_FILE = path.join(__dirname, 'database.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Also serve index.html if placed in root directory
app.use(express.static(__dirname));

// Initialize Persistent Database with Demo Seed Data
function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      users: [
        {
          id: 'usr_demo_1',
          email: 'ramesh.deshmukh@gmail.com',
          name: 'Rameshwar Deshmukh',
          picture: 'https://ui-avatars.com/api/?name=Rameshwar+Deshmukh&background=0369A1&color=fff&bold=true',
          phone: '9823011223',
          age: '68',
          address: 'N-4 CIDCO, Chhatrapati Sambhajinagar',
          createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
          lastActive: new Date(Date.now() - 3600000).toISOString()
        },
        {
          id: 'usr_demo_2',
          email: 'sunita.kulkarni@gmail.com',
          name: 'Sunita Kulkarni',
          picture: 'https://ui-avatars.com/api/?name=Sunita+Kulkarni&background=0284C7&color=fff&bold=true',
          phone: '9422099887',
          age: '71',
          address: 'Garkheda Parisar, Chhatrapati Sambhajinagar',
          createdAt: new Date(Date.now() - 86400000).toISOString(),
          lastActive: new Date(Date.now() - 1800000).toISOString()
        }
      ],
      bookings: [
        {
          id: 'EE-89412031',
          userId: 'usr_demo_2',
          userEmail: 'sunita.kulkarni@gmail.com',
          userName: 'Sunita Kulkarni',
          type: 'APPOINTMENT',
          title: 'Dr. Hedgewar Hospital',
          patientName: 'Sunita Kulkarni',
          phone: '9422099887',
          age: '71',
          department: 'Cardiology & General Checkup',
          date: '2026-10-28',
          time: 'Morning',
          reason: 'Routine BP and ECG checkup',
          createdAt: new Date(Date.now() - 1800000).toLocaleString(),
          timestamp: Date.now() - 1800000
        },
        {
          id: 'EE-77231904',
          userId: 'usr_demo_1',
          userEmail: 'ramesh.deshmukh@gmail.com',
          userName: 'Rameshwar Deshmukh',
          type: 'VOLUNTEER',
          title: 'Student Volunteer Home Visit',
          patientName: 'Rameshwar Deshmukh',
          phone: '9823011223',
          age: '68',
          department: 'Shravanbal Pension Form Help',
          date: '2026-10-25',
          time: 'Afternoon',
          reason: 'Assistance with online pension form upload',
          createdAt: new Date(Date.now() - 3600000).toLocaleString(),
          timestamp: Date.now() - 3600000
        }
      ]
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
  }
}

function readDB() {
  initDB();
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return { users: [], bookings: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// 1. Google Login / Register Endpoint
app.post('/api/auth/google', (req, res) => {
  const { email, name, picture, phone, age, address } = req.body;
  if (!email || !name) {
    return res.status(400).json({ error: 'Email and Name are required' });
  }

  const db = readDB();
  let user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  const now = new Date().toISOString();

  if (!user) {
    user = {
      id: 'usr_' + Date.now().toString(36),
      email,
      name,
      picture: picture || `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=0369A1&color=fff&bold=true`,
      phone: phone || '',
      age: age || '',
      address: address || 'Chhatrapati Sambhajinagar',
      createdAt: now,
      lastActive: now
    };
    db.users.unshift(user);
  } else {
    user.name = name || user.name;
    if (picture) user.picture = picture;
    user.lastActive = now;
  }

  writeDB(db);
  res.json({ success: true, user });
});

// 2. Update User Profile Endpoint
app.put('/api/user/profile', (req, res) => {
  const { id, email, name, phone, age, address } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.id === id || (email && u.email.toLowerCase() === email.toLowerCase()));
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (name !== undefined) user.name = name;
  if (phone !== undefined) user.phone = phone;
  if (age !== undefined) user.age = age;
  if (address !== undefined) user.address = address;
  user.picture = `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name)}&background=0369A1&color=fff&bold=true`;
  user.lastActive = new Date().toISOString();

  writeDB(db);
  res.json({ success: true, user });
});

// 3. Create Booking (Appointment or Volunteer Request)
app.post('/api/bookings', (req, res) => {
  const { userId, userEmail, userName, type, title, patientName, phone, age, department, date, time, reason } = req.body;
  if (!userId && !userEmail) {
    return res.status(401).json({ error: 'Authentication required to book' });
  }

  const db = readDB();
  const user = db.users.find(u => u.id === userId || (userEmail && u.email.toLowerCase() === userEmail.toLowerCase()));
  const nowIso = new Date().toISOString();

  if (user) {
    user.lastActive = nowIso;
    if (phone && !user.phone) user.phone = phone;
    if (age && !user.age) user.age = age;
  }

  const booking = {
    id: 'EE-' + Date.now().toString().slice(-8),
    userId: user ? user.id : userId,
    userEmail: user ? user.email : userEmail,
    userName: user ? user.name : userName,
    type: type || 'APPOINTMENT',
    title: title || 'Hospital Appointment',
    patientName: patientName || (user ? user.name : 'Senior Citizen'),
    phone: phone || (user ? user.phone : ''),
    age: age || (user ? user.age : ''),
    department: department || 'General Consultation',
    date: date || new Date().toISOString().slice(0, 10),
    time: time || 'Morning',
    reason: reason || 'Standard consultation / assistance',
    createdAt: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    timestamp: Date.now()
  };

  db.bookings.unshift(booking);
  writeDB(db);
  res.json({ success: true, booking, user });
});

// 4. Get Logged-In User's Booking History
app.get('/api/bookings/user/:email', (req, res) => {
  const email = (req.params.email || '').toLowerCase();
  const db = readDB();
  const userBookings = db.bookings
    .filter(b => (b.userEmail || '').toLowerCase() === email)
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  res.json({ success: true, bookings: userBookings });
});

// 5. Delete Booking
app.delete('/api/bookings/:id', (req, res) => {
  const db = readDB();
  db.bookings = db.bookings.filter(b => b.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// 6. Developer Console Verification & Ranked Users Data
app.post('/api/dev/overview', (req, res) => {
  const { password } = req.body;
  if (!password || password !== DEV_PASSWORD) {
    return res.status(403).json({ success: false, error: 'Invalid Developer Key' });
  }

  const db = readDB();
  const rankedUsers = [...db.users]
    .map(u => {
      const userBookings = db.bookings
        .filter(b => b.userId === u.id || (b.userEmail && b.userEmail.toLowerCase() === u.email.toLowerCase()))
        .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      const latestTimestamp = userBookings.length
        ? Math.max(new Date(u.lastActive || u.createdAt).getTime(), userBookings[0].timestamp || 0)
        : new Date(u.lastActive || u.createdAt).getTime();

      return {
        ...u,
        bookingCount: userBookings.length,
        bookings: userBookings,
        sortTime: latestTimestamp
      };
    })
    .sort((a, b) => b.sortTime - a.sortTime);

  res.json({
    success: true,
    totalUsers: rankedUsers.length,
    totalBookings: db.bookings.length,
    users: rankedUsers
  });
});

// Fallback to index.html (supports both public/index.html and root index.html)
app.get('*', (req, res) => {
  const publicIndex = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(publicIndex)) {
    res.sendFile(publicIndex);
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.listen(PORT, () => {
  initDB();
  console.log(`ElderEase Server running on port ${PORT}`);
});
