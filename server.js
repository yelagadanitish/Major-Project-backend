require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const { exec, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");

const User = require("./models/User");
const Project = require("./models/Project");

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Google OAuth Client
const GOOGLE_CLIENT_ID = process.env.REACT_APP_GOOGLE_CLIENT_ID || "1041633394834-2quj1e8asfqjcj1jvt1v1v4q2r0p0q2r.apps.googleusercontent.com";
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Initialize Email Transporter (Gmail)
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

/* ---------------- MONGODB ---------------- */

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB Connected"))
.catch(err=>console.log(err));

/* ---------------- AUTH ---------------- */

const authMiddleware = (req,res,next)=>{

const token = req.header("Authorization");

if(!token) return res.status(401).json({message:"No token"});

try{

const verified = jwt.verify(
token.replace("Bearer ",""),
process.env.JWT_SECRET
);

req.user = verified;

next();

}catch{

res.status(401).json({message:"Invalid token"});

}

};

/* -------- VERIFICATION CODES STORAGE -------- */
// In production, use a database collection instead
const verificationCodes = new Map();

/* -------- EMAIL VERIFICATION ENDPOINTS -------- */

// Send verification code to email
app.post("/api/send-verification", async(req,res)=>{

const {email} = req.body;

if(!email) return res.status(400).json({message:"Email required"});

// Validate email format
const emailRegex = /^[^\s@]{1,64}@[^\s@]{1,255}\.[a-zA-Z]{2,}$/;
if(!emailRegex.test(email)) return res.status(400).json({message:"Invalid email format"});

// Check if user already exists
const existing = await User.findOne({email});
if(existing) return res.status(400).json({message:"Email already registered"});

// Generate 6-digit code
const code = Math.floor(100000 + Math.random() * 900000).toString();

// Store code with 10 minute expiry
verificationCodes.set(email, {code, expiresAt: Date.now() + 10 * 60 * 1000});

try {
  // Send verification code via email
  await emailTransporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your Email Verification Code",
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
        <div style="background-color: white; padding: 30px; border-radius: 8px; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #333; margin-bottom: 20px;">Email Verification</h2>
          <p style="color: #666; font-size: 16px; margin-bottom: 20px;">
            Your verification code is:
          </p>
          <div style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; text-align: center; margin-bottom: 20px;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #007bff;">${code}</span>
          </div>
          <p style="color: #999; font-size: 14px;">
            This code will expire in 10 minutes. Do not share this code with anyone.
          </p>
        </div>
      </div>
    `
  });
  
  res.json({success:true, message:"Verification code sent to email"});
} catch(err) {
  console.error("Failed to send verification email:", err);
  res.status(500).json({message:"Failed to send email. Check server configuration."});
}

});

// Verify code
app.post("/api/verify-code", async(req,res)=>{

const {email, code} = req.body;

if(!email || !code) return res.status(400).json({message:"Email and code required"});

const stored = verificationCodes.get(email);

if(!stored) return res.status(400).json({message:"No verification code found for this email"});

if(stored.expiresAt < Date.now()) return res.status(400).json({message:"Verification code expired"});

if(stored.code !== code) return res.status(400).json({message:"Invalid verification code"});

// Code is valid, mark email as verified
verificationCodes.delete(email);

res.json({success:true, message:"Email verified successfully"});

});

/* ---------------- REGISTER ---------------- */

app.post("/api/register",async(req,res)=>{

const {email,password} = req.body;

const existing = await User.findOne({email});

if(existing) return res.status(400).json({message:"User exists"});

const hashed = await bcrypt.hash(password,10);

const user = new User({
email,
password:hashed
});

await user.save();

res.json({message:"Registered"});

});

/* ---------------- LOGIN ---------------- */

app.post("/api/login",async(req,res)=>{

const {email,password} = req.body;

const user = await User.findOne({email});

if(!user) return res.status(400).json({message:"Invalid"});

const match = await bcrypt.compare(password,user.password);

if(!match) return res.status(400).json({message:"Invalid"});

const token = jwt.sign(
{id:user._id,email:user.email},
process.env.JWT_SECRET,
{expiresIn:"1d"}
);

res.json({token});

});

/* -------- OAUTH AUTHENTICATION -------- */

// Google OAuth - Verify and Create/Login User
app.post("/api/auth/google", async(req,res)=>{
  try {
    const {token} = req.body;
    
    if(!token) return res.status(400).json({message:"Token required"});
    
    // Verify the Google JWT token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: "1041633394834-2quj1e8asfqjcj1jvt1v1v4q2r0p0q2r.apps.googleusercontent.com"
    });
    
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;
    
    if(!email) return res.status(400).json({message:"Email not found in token"});
    
    // Find existing user or create new one
    let user = await User.findOne({email});
    
    if(!user){
      // Create new user from Google OAuth
      user = new User({
        email,
        password: "oauth_google_" + Math.random().toString(36).substring(7),
      });
      await user.save();
      console.log("New user created via Google OAuth:", email);
    }
    
    // Generate JWT token for our app
    const appToken = jwt.sign(
      {id: user._id, email: user.email},
      process.env.JWT_SECRET,
      {expiresIn: "7d"}
    );
    
    res.json({token: appToken, email: user.email, success: true});
    
  } catch(err) {
    console.error("Google OAuth error:", err);
    res.status(400).json({message: "Google authentication failed", error: err.message});
  }
});

// GitHub OAuth - Handle Callback
app.get("/api/auth/github/callback", async(req,res)=>{
  try {
    const {code} = req.query;
    
    if(!code) return res.status(400).json({message:"Code required"});
    
    // Exchange code for access token
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code: code
      },
      {headers: {Accept: "application/json"}}
    );
    
    if(!tokenResponse.data.access_token) {
      console.error("GitHub token error:", tokenResponse.data);
      return res.redirect(`http://localhost:3000/login?error=github_auth_failed`);
    }
    
    const accessToken = tokenResponse.data.access_token;
    
    // Get user email from GitHub
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: {Authorization: `Bearer ${accessToken}`}
    });
    
    let email = userResponse.data.email;
    
    // If email is private, fetch from emails endpoint
    if(!email) {
      const emailResponse = await axios.get("https://api.github.com/user/emails", {
        headers: {Authorization: `Bearer ${accessToken}`}
      });
      email = emailResponse.data.find(e => e.primary)?.email;
    }
    
    if(!email) return res.redirect(`http://localhost:3000/login?error=no_email_from_github`);
    
    // Find or create user
    let user = await User.findOne({email});
    
    if(!user){
      user = new User({
        email,
        password: "oauth_github_" + Math.random().toString(36).substring(7),
      });
      await user.save();
      console.log("New user created via GitHub OAuth:", email);
    }
    
    // Generate JWT token
    const appToken = jwt.sign(
      {id: user._id, email: user.email},
      process.env.JWT_SECRET,
      {expiresIn: "7d"}
    );
    
    // Redirect back to frontend with token
    res.redirect(`http://localhost:3000/auth-callback?token=${appToken}&email=${email}`);
    
  } catch(err) {
    console.error("GitHub OAuth error:", err);
    res.redirect(`http://localhost:3000/login?error=github_auth_failed`);
  }
});

/* ---------------- PROJECT APIs ---------------- */

app.post("/api/projects", authMiddleware, async (req, res) => {

const { name } = req.body;

const project = new Project({
name,
owner: req.user.id,
files: [
{
name: "main.js",
content: "",
language: "javascript"
}
]
});

await project.save();

res.json(project);

});

app.get("/api/projects", authMiddleware, async (req, res) => {

const projects = await Project.find({
owner: req.user.id
});

res.json(projects);

});

app.get("/api/projects/:id", authMiddleware, async (req, res) => {

const project = await Project.findById(req.params.id);

res.json(project);

});

/* ---------------- FILE APIs ---------------- */

app.get("/api/projects/:id/files", authMiddleware, async (req,res)=>{

const project = await Project.findById(req.params.id);

res.json(project.files);

});

app.post("/api/projects/:id/files", authMiddleware, async (req,res)=>{

const { name, language } = req.body;

const project = await Project.findById(req.params.id);

project.files.push({
name,
content:"",
language
});

await project.save();

res.json(project.files);

});

app.put("/api/projects/:id/files/:fileIndex", authMiddleware, async (req,res)=>{

const { content } = req.body;

const project = await Project.findById(req.params.id);

project.files[req.params.fileIndex].content = content;

project.updatedAt = Date.now();

await project.save();

res.json(project.files);

});

/* ---------------- ANALYSIS ---------------- */

app.post("/api/offline-analyze",authMiddleware,(req,res)=>{

const {code,language} = req.body;

if(!code) return res.json({issues:[]});

if(language==="javascript"){

let issues=[];

try{

const ast = parser.parse(code,{
sourceType:"module",
plugins:["jsx"],
errorRecovery:true,
locations:true
});

traverse(ast,{
VariableDeclaration(path){
if(path.node.kind==="var"){
issues.push({
type:"warning",
message:"Avoid using var",
line:path.node.loc.start.line
});
}
}
});

}catch{

issues.push({
type:"error",
message:"Syntax Error detected",
line:null
});

}

return res.json({issues});

}

if(language==="python"){

const scriptPath = path.join(__dirname,"pythonAnalyzer.py");

const py = spawn("python",[scriptPath]);

let output="";

py.stdin.write(code);
py.stdin.end();

py.stdout.on("data",(data)=>{
output += data.toString();
});

py.on("close",()=>{

try{

const issues = JSON.parse(output);

res.json({issues});

}catch{

res.json({issues:[]});

}

});

return;

}

res.json({issues:[]});

});

/* ---------------- AI ANALYSIS WITH GROQ API ---------------- */

app.post("/api/ai-review", authMiddleware, async (req, res) => {

  const { code, language } = req.body;

  if (!code) return res.json({ issues: [], fixedCode: "", summary: "No code provided." });

  try {
    const codeLines = code.split('\n');
    
    const prompt = `You are a senior software engineer performing professional code review. Analyze the following ${language} code for:
1. Bugs and logical errors
2. Security vulnerabilities
3. Performance issues
4. Bad practices and code smell
5. Missing error handling
6. Type safety issues
7. Code style improvements

Return ONLY valid JSON (no markdown, no extra text) with EXACTLY this structure:
{
  "issues": [
    {
      "line": <line_number>,
      "type": "error|warning|suggestion",
      "message": "<2-3 sentence explanation of WHY this is wrong>",
      "explanation": "<detailed explanation of impact and consequences>",
      "fix": "<corrected line of code>"
    }
  ],
  "fixedCode": "<complete corrected code with all issues fixed>",
  "summary": "<1-2 sentence overall assessment>"
}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

CRITICAL REQUIREMENTS:
- Line numbers MUST match the input code
- fixedCode must be complete and executable
- Include ALL necessary fixes in fixedCode
- Return ONLY valid JSON, no explanations outside JSON
- Each issue must have UNIQUE line number (no duplicates)`;

    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "llama3-8b-8192",
        messages: [
          {
            role: "system",
            content: "You are an expert code reviewer. Always respond with ONLY valid JSON, never add markdown or extra text."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        temperature: 0.3,
        max_tokens: 4000
      },
      {
        headers: {
          "Authorization": `Bearer ${process.env.GROQ_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    let aiResponse = response.data.choices[0].message.content.trim();
    
    // Remove markdown code blocks if present
    if (aiResponse.startsWith("```")) {
      aiResponse = aiResponse.replace(/^```[\w]*\n/, "").replace(/\n```$/, "");
    }

    // Parse JSON safely
    let parsedResponse;
    try {
      parsedResponse = JSON.parse(aiResponse);
    } catch (parseError) {
      console.error("Failed to parse Groq response:", aiResponse);
      return res.status(500).json({
        issues: [],
        fixedCode: code,
        summary: "Unable to parse AI response. Please try again.",
        error: "JSON parse error"
      });
    }

    // Validate and sanitize response
    const validatedIssues = Array.isArray(parsedResponse.issues) 
      ? parsedResponse.issues.filter(issue => 
          typeof issue.line === 'number' && 
          issue.line > 0 &&
          issue.line <= codeLines.length &&
          ['error', 'warning', 'suggestion'].includes(issue.type) &&
          typeof issue.message === 'string'
        ).map(issue => ({
          line: issue.line,
          type: issue.type,
          message: issue.message,
          explanation: typeof issue.explanation === 'string' ? issue.explanation : issue.message,
          fix: typeof issue.fix === 'string' ? issue.fix : ""
        }))
      : [];

    const fixedCode = typeof parsedResponse.fixedCode === 'string' 
      ? parsedResponse.fixedCode 
      : code;

    const summary = typeof parsedResponse.summary === 'string' 
      ? parsedResponse.summary 
      : "Analysis complete."

    res.json({
      issues: validatedIssues,
      fixedCode: fixedCode,
      summary: summary
    });

  } catch (error) {
    console.error("AI Review error:", error.response?.data || error.message);
    res.status(500).json({
      error: error.response?.data?.error?.message || error.message,
      issues: [],
      fixedCode: code,
      summary: "An error occurred during analysis. Please try again."
    });
  }

});

/* ---------------- EXECUTION ---------------- */

app.post("/api/execute",authMiddleware,(req,res)=>{

const {code,language} = req.body;

const sandbox = path.join(__dirname,"sandbox");

if(!fs.existsSync(sandbox)){
fs.mkdirSync(sandbox);
}

let command;

if(language==="javascript"){

const file = path.join(sandbox,"temp.js");
fs.writeFileSync(file,code);

command=`node "${file}"`;

}

else if(language==="python"){

const file = path.join(sandbox,"temp.py");
fs.writeFileSync(file,code);

command=`python "${file}"`;

}

else if(language==="c"){

const src = path.join(sandbox,"temp.c");
const out = path.join(sandbox,"temp_c.exe");

fs.writeFileSync(src,code);

command=`gcc "${src}" -o "${out}" && "${out}"`;

}

else if(language==="cpp"){

const src = path.join(sandbox,"temp.cpp");
const out = path.join(sandbox,"temp_cpp.exe");

fs.writeFileSync(src,code);

command=`g++ "${src}" -o "${out}" && "${out}"`;

}

else if(language==="java"){

const src = path.join(sandbox,"Main.java");

fs.writeFileSync(src,code);

command=`javac "${src}" && java -cp "${sandbox}" Main`;

}

exec(command,{timeout:5000},(err,stdout,stderr)=>{

if(err){
return res.json({output:stderr || err.message});
}

res.json({output:stdout});

});

});

/* ---------------- SOCKET.IO ---------------- */

const server = http.createServer(app);

const io = new Server(server,{
cors:{origin:"http://localhost:3000"}
});

io.on("connection",(socket)=>{

socket.on("createRoom",()=>{

const roomId = Math.random().toString(36).substring(2,8);

socket.join(roomId);

socket.emit("roomCreated",roomId);

});

socket.on("joinRoom",(roomId)=>{

socket.join(roomId);

const clients = io.sockets.adapter.rooms.get(roomId);

const count = clients ? clients.size : 0;

io.to(roomId).emit("roomUsers",count);

});

socket.on("codeChange",({roomId,code})=>{
socket.to(roomId).emit("receiveCode",code);
});

socket.on("cursorMove",({roomId,position,user,color})=>{
socket.to(roomId).emit("receiveCursor",{position,user,color});
});

socket.on("sendMessage",({roomId,message,user})=>{
io.to(roomId).emit("receiveMessage",{
message,
user,
time:new Date().toLocaleTimeString()
});
});

});

server.listen(5000,()=>{
console.log("Server running on port 5000");
});