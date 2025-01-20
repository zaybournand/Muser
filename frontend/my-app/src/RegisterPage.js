import React, { useState } from 'react';
import './App.css';

function RegisterPage() {
  const [messages, setMessages] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
  
    // Reset messages
    setMessages([]);
  
    // Check if passwords match before sending the request
    if (password !== confirmPassword) {
      setMessages([{ category: 'error', message: 'Passwords do not match.' }]);
      return;
    }
  
    // Send data to backend (Flask) for registration
    try {
      const response = await fetch('http://localhost:5000/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, confirm_password: confirmPassword, username, user_type: 'student' }),
      });
  
      const data = await response.json();
  
      if (data.success) {
        setMessages([{ category: 'success', message: data.message }]);
      } else {
        setMessages([{ category: 'error', message: data.message || 'Something went wrong.' }]);
      }
    } catch (error) {
      setMessages([{ category: 'error', message: 'Error connecting to the server.' }]);
    }
  };
  

  return (
    <div className="auth-page">
      <div className="auth-container">
        <h2>Register</h2>

        {messages.length > 0 && (
          <ul className="flash-messages">
            {messages.map((msg, index) => (
              <li key={index} className={msg.category}>
                {msg.message}
              </li>
            ))}
          </ul>
        )}

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            placeholder="Email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            name="password"
            placeholder="Password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <label htmlFor="confirm_password">Confirm Password</label>
          <input
            type="password"
            id="confirm_password"
            name="confirm_password"
            placeholder="Confirm Password"
            required
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          <button type="submit">Register</button>
        </form>

        <p>
          Already have an account? <a href="./LoginPage">Login here</a>
        </p>
      </div>
    </div>
  );
}

export default RegisterPage;
