const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🔑 Secret key for JWT
const JWT_SECRET = "supersecretkey123"; // change to env var in production

// ✅ Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/bloodconnectDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB connection error:", err));

// ✅ Donor Schema
const donorSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  bloodGroup: String,
  location: String,
  password: String, // for login
});
const Donor = mongoose.model("Donor", donorSchema);

// ✅ Hospital Schema
const hospitalSchema = new mongoose.Schema({
  hospitalName: String,
  email: { type: String, unique: true },
  phone: String,
  address: String,
  city: String,
  blood: [
    {
      type: { type: String }, // "O+", "A-", etc.
      units: { type: Number, default: 0 }
    }
  ],
  password: String,
  isAdmin: { type: Boolean, default: false } // ✅ Admin flag
});

const Hospital = mongoose.model("Hospital", hospitalSchema);

//// ------------------- AUTH MIDDLEWARE ------------------- ////
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = decoded; // contains { id, role }
    next();
  });
};

//// ------------------- ROUTES ------------------- ////

// ✅ Donor Registration
// Donor Registration
app.post("/api/donors/register", async (req, res) => {
  try {
    const { name, email, phone, bloodGroup, location, password } = req.body;

    if (!name || !email || !phone || !bloodGroup || !location || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingDonor = await Donor.findOne({ email });
    if (existingDonor) {
      return res.status(400).json({ message: "Donor already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const donor = new Donor({
      name,
      email,
      phone,
      bloodGroup,
      location,
      password: hashedPassword,
    });

    await donor.save();

    const token = jwt.sign({ id: donor._id, role: "donor" }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Donor registered successfully", token });
  } catch (err) {
    console.error("❌ Donor Registration Error:", err);
    res.status(500).json({ message: "Error registering donor", error: err.message });
  }
});

    

// ✅ Hospital Registration
app.post("/register-hospital", async (req, res) => {
  try {
    const { hospitalName, email, phone, address, city, blood, password } = req.body;

    if (!hospitalName || !email || !phone || !address || !city || !blood || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!Array.isArray(blood) || blood.some(b => !b.type || typeof b.units !== "number")) {
      return res.status(400).json({ message: "Blood must be an array of {type, units}" });
    }

    const existingHospital = await Hospital.findOne({ email });
    if (existingHospital) {
      return res.status(400).json({ message: "Hospital already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const hospital = new Hospital({
      hospitalName,
      email,
      phone,
      address,
      city,
      blood,
      password: hashedPassword
    });

    await hospital.save();

    const token = jwt.sign({ id: hospital._id, role: "hospital" }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(201).json({ message: "Hospital registered successfully", token });
  } catch (err) {
    console.error("❌ Hospital Registration Error:", err);  // <— log the full error
    res.status(500).json({ message: "Error registering hospital", error: err.message });
  }
});

// ✅ Donor Login
// ✅ Donor Login (fixed to send name)
app.post("/login-donor", async (req, res) => {
  const { email, password } = req.body;
  const donor = await Donor.findOne({ email });
  if (!donor) return res.status(400).json({ message: "Donor not found" });

  const isMatch = await bcrypt.compare(password, donor.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: donor._id, role: "donor" }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ message: "Login successful", token, name: donor.name });
});



// ✅ Hospital Login (fixed to send name)
app.post("/login-hospital", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hospital = await Hospital.findOne({ email });
    if (!hospital) return res.status(400).json({ message: "Hospital not found" });

    const isMatch = await bcrypt.compare(password, hospital.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: hospital._id, role: "hospital", isAdmin: hospital.isAdmin },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      hospitalName: hospital.hospitalName,
      blood: hospital.blood
    });
  } catch (err) {
    console.error("❌ Hospital login error:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== "hospital" || !req.user.isAdmin) {
    return res.status(403).json({ message: "Access denied: Admins only" });
  }
  next();
};

// Example admin route
app.get("/hospital-admin-data", authMiddleware, adminMiddleware, async (req, res) => {
  const hospital = await Hospital.findById(req.user.id).select("-password");
  res.json({ hospital });
});



// ✅ Find Blood (includes hospital blood units)
app.post("/find-blood", async (req, res) => {
  try {
    const { bloodGroup, location } = req.body;

    const donors = await Donor.find({ bloodGroup, location });

    const hospitals = await Hospital.find({
      city: location,
      "blood.type": bloodGroup   // ✅ correct nested query
    }).select("-password");

    if (donors.length > 0 || hospitals.length > 0) {
      return res.json({ found: true, donors, hospitals });
    } else {
      return res.json({ found: false, donors: [], hospitals: [] });
    }
  } catch (err) {
    res.status(500).json({ message: "Error searching blood", error: err });
  }
});


// ✅ Get Donor Dashboard Data
app.get("/donor-dashboard", authMiddleware, async (req, res) => {
  if (req.user.role !== "donor")
    return res.status(403).json({ message: "Access denied" });

  const donor = await Donor.findById(req.user.id).select("-password");
  res.json({ message: `Welcome ${donor.name}`, donor });
});

// ✅ Get Hospital Dashboard Data
app.get("/hospital-dashboard", authMiddleware, async (req, res) => {
  if (req.user.role !== "hospital")
    return res.status(403).json({ message: "Access denied" });

  const hospital = await Hospital.findById(req.user.id).select("-password");
  res.json({ message: `Welcome ${hospital.hospitalName}`, hospital });
});

// ✅ Find Blood
app.post("/find-blood", async (req, res) => {
  try {
    const { bloodGroup, location } = req.body;

    const donors = await Donor.find({ bloodGroup, location });

    const hospitals = await Hospital.find({
      city: location,
      blood: { $in: [bloodGroup] },
    });

    if (donors.length > 0 || hospitals.length > 0) {
      return res.json({ found: true, donors, hospitals });
    } else {
      return res.json({ found: false, donors: [], hospitals: [] });
    }
  } catch (err) {
    res.status(500).json({ message: "Error searching blood", error: err });
  }
});


//// ------------------- STATIC FRONTEND ------------------- ////
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

//// ------------------- SERVER START ------------------- ////
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
