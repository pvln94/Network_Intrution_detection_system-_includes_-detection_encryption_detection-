import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom';

// Mock user credentials
const users = [
  { username: 'user1', password: 'pass1', role: 'user1' },
  { username: 'user2', password: 'pass2', role: 'user2' }
];

// Background image style
const backgroundStyle = {
  backgroundImage: 'url("https://www.clearnetwork.com/wp-content/uploads/2019/03/AdobeStock_200146313-1080x675.jpeg")',
  backgroundSize: '100% 100%', // This will stretch to cover entire screen
  backgroundPosition: 'center',
  backgroundRepeat: 'no-repeat',
  minHeight: '100vh',
  display: 'flex',
  flexDirection: 'column',
  width: '100vw', // Ensure it covers full viewport width
  height: '100vh', // Ensure it covers full viewport height
  position: 'fixed', // This prevents scrolling from affecting the background
  top: 0,
  left: 0,
  maxHeight: '90vh', // Limit height to viewport
  overflowY: 'auto'  // Enable vertical scrolling
};

function HomePage() {
  const navigate = useNavigate();

  return (
    <div style={{ 
      ...backgroundStyle,
      alignItems: 'center',
      justifyContent: 'center',
      textAlign: 'center',
      color: 'white',
      textShadow: '2px 2px 4px rgba(0, 0, 0, 0.5)'
    }}>
      <div style={{
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        padding: '40px',
        borderRadius: '10px',
        maxWidth: '800px',
        margin: '0 20px',
        color: 'white',
      }}>
        <h1 style={{ fontSize: '3rem', marginBottom: '20px' }}>Network Intrusion Detection System</h1>
        <p style={{ fontSize: '1.2rem', marginBottom: '30px', color: 'white' }}>
          ( Secure your network data with our advanced intrusion detection technology ) 
        </p>
        <div style={{
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          padding: '40px',
          borderRadius: '10px',
          maxWidth: '800px',
          margin: '0 20px'
        }}>
          <h3 style={{ marginTop: '0',color: 'white' }}>How It Works:</h3>
          <ol style={{ paddingLeft: '20px', marginBottom: '0' }}>
            <li style={{ marginBottom: '10px' }}>
              We analyze network packet features using our machine learning model
            </li>
            <p>


            </p>
            <li style={{ marginBottom: '10px' }}>
              The system classifies potential intrusion types in real-time
            </li>
            <p>

              
            </p>
            <li>
              For secure sharing:
              <p>

              
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '5px' }}>
                <li>Features and predictions are encrypted using AES</li>
                <li>The AES key is then encrypted with RSA for transmission</li>
                <li>Authenticated users decrypt the AES key with their RSA private key</li>
                <li>Final decryption reveals the original packet data and predictions</li>
              </ul>
            </li>
          </ol>
        </div>
        <button 
          onClick={() => navigate('/login')}
          style={{
            padding: '12px 30px',
            fontSize: '1.2rem',
            backgroundColor: '#4CAF50',
            color: 'white',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer',
            transition: 'background-color 0.3s'
          }}
          onMouseOver={(e) => e.target.style.backgroundColor = '#45a049'}
          onMouseOut={(e) => e.target.style.backgroundColor = '#4CAF50'}
        >
          Login
        </button>
      </div>
    </div>
  );
}

function Login({ setUser }) {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Simulate API call delay
    setTimeout(() => {
      const user = users.find(u => u.username === credentials.username && u.password === credentials.password);
      if (user) {
        setUser(user);
        navigate('/dashboard');
      } else {
        setError('Invalid credentials');
      }
      setLoading(false);
    }, 1000);
  };

  return (
    <div style={{ 
      ...backgroundStyle,
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      <div style={{
        backgroundColor: 'rgba(255, 255, 255, 0.9)',
        padding: '40px',
        borderRadius: '10px',
        boxShadow: '0 4px 8px rgba(0, 0, 0, 0.2)',
        width: '100%',
        maxWidth: '400px'
      }}>
        <h1 style={{ textAlign: 'center', marginBottom: '30px', color: '#333' }}>Login</h1>
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', color: '#555' }}>Username</label>
            <input
              type="text"
              value={credentials.username}
              onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
              style={{ 
                width: '100%', 
                padding: '12px',
                borderRadius: '4px',
                border: '1px solid #ddd',
                fontSize: '16px'
              }}
              required
            />
          </div>
          <div style={{ marginBottom: '30px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', color: '#555' }}>Password</label>
            <input
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
              style={{ 
                width: '100%', 
                padding: '12px',
                borderRadius: '4px',
                border: '1px solid #ddd',
                fontSize: '16px'
              }}
              required
            />
          </div>
          <button 
            type="submit" 
            disabled={loading}
            style={{ 
              width: '100%', 
              padding: '12px',
              backgroundColor: loading ? '#999' : '#4CAF50',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              fontSize: '16px',
              cursor: 'pointer',
              transition: 'background-color 0.3s'
            }}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        {error && <p style={{ color: 'red', marginTop: '20px', textAlign: 'center' }}>{error}</p>}
      </div>
    </div>
  );
}

function Dashboard({ user }) {
  const [status, setStatus] = useState('');
  const [logs, setLogs] = useState([]);
  const [logMessage, setLogMessage] = useState('');
  const [decryptedLog, setDecryptedLog] = useState('');
  const [loading, setLoading] = useState(false);
  const [captureResult, setCaptureResult] = useState(null);
  const navigate = useNavigate();

  const capturePacket = async () => {
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/capture");
      const data = await response.json();
      setCaptureResult(data); // Store the detailed result
      setStatus(data.status === "Intrusion" ? `⚠️ Intrusion Detected: ${data.type}` : "✅ No Intrusion Detected");
    } catch (error) {
      console.error("Error:", error);
      setStatus("❌ Error capturing packet");
      setCaptureResult(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/user2/logs");
      const data = await response.json();
      setLogs(data.encrypted_logs || []);
      setLogMessage(data.message || (data.encrypted_logs?.length === 0 ? "No logs found." : ''));
    } catch (error) {
      console.error("Error fetching logs:", error);
      setLogMessage("❌ Error fetching logs");
    } finally {
      setLoading(false);
    }
  };

  const decryptLog = async () => {
    setLoading(true);
    try {
      if (logs.length === 0) {
        setDecryptedLog([]);
        setLogMessage("No logs available for decryption.");
        return;
      }

      const encrypted_aes_key = logs[0].encrypted_aes_key;
      if (!encrypted_aes_key) {
        setDecryptedLog([]);
        setLogMessage("❌ Error: Missing encrypted AES key in logs.");
        return;
      }

      const response = await fetch("http://127.0.0.1:5000/user2/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encrypted_aes_key: encrypted_aes_key,
          encrypted_logs: logs
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      const data = await response.json();
      setDecryptedLog(data.decrypted_logs || []);
      setLogMessage(data.message || "Decryption successful.");
    } catch (error) {
      console.error("Error decrypting log:", error);
      setDecryptedLog([]);
      setLogMessage("❌ Error decrypting logs. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  if (user.role === 'user2') {
    return (
      <div style={{ 
        ...backgroundStyle,
        padding: '20px',
        backgroundColor: 'rgba(255, 255, 255, 0.9)'
      }}>
        <div style={{ 
          maxWidth: '1000px', 
          margin: '0 auto',
          backgroundColor: 'white',
          padding: '30px',
          borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)'
        }}>
          <h1 style={{ color: '#333', borderBottom: '1px solid #eee', paddingBottom: '10px' }}>Hi User2</h1>
          <button 
            onClick={fetchLogs} 
            disabled={loading}
            style={{
              padding: '10px 20px',
              backgroundColor: '#4CAF50',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              marginBottom: '20px',
              fontSize: '16px'
            }}
          >
            {loading ? 'Fetching logs...' : 'Fetch Logs'}
          </button>

          {logs.length > 0 ? (
            <div>
              <h2 style={{ color: '#444' }}>Encrypted Logs</h2>
              <ul style={{ listStyle: 'none', padding: 0 }}>
                {logs.map((log, index) => (
                  <li key={index} style={{ 
                    marginBottom: '20px', 
                    color: '#444',
                    border: '1px solid #ddd', 
                    padding: '15px', 
                    borderRadius: '5px',
                    backgroundColor: '#f9f9f9'
                  }}>
                    <strong style={{ color: '#444' }}>Log {index + 1}:</strong>
                    <div style={{ marginTop: '10px' }}>
                      <strong>Encrypted Features:</strong> {JSON.stringify(log.encrypted_features)}
                    </div>
                    <div style={{ marginTop: '5px' }}>
                      <strong>Encrypted Prediction:</strong> {log.encrypted_prediction}
                    </div>
                    <div style={{ marginTop: '5px' }}>
                      <strong>Encrypted AES Key:</strong> {log.encrypted_aes_key}
                    </div>
                    <div style={{ marginTop: '5px' }}>
                      <strong>IV:</strong> {log.iv || 'N/A'}
                    </div>
                  </li>
                ))}
              </ul>

              <button
                onClick={decryptLog}
                disabled={loading || logs.length === 0}
                style={{
                  padding: '10px 20px',
                  backgroundColor: '#2196F3',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  marginBottom: '20px',
                  fontSize: '16px'
                }}
              >
                {loading ? 'Decrypting...' : 'Decrypt Log'}
              </button>

              {decryptedLog.length > 0 ? (
                <div>
                  <h3 style={{ color: '#444' }}>Decrypted Logs</h3>
                  <ul style={{ listStyle: 'none', padding: 0 }}>
                    {decryptedLog.map((log, index) => (
                      <li key={index} style={{ 
                        marginBottom: '20px', 
                        border: '1px solid #ddd', 
                        padding: '15px', 
                        borderRadius: '5px',
                        backgroundColor: '#f0f8ff',
                        color: '#444'
                      }}>
                        <strong style={{ color: '#333' }}>Decrypted Log {index + 1}:</strong>
                        <div style={{ marginTop: '10px' }}>
                          <strong>Decrypted Features:</strong> 
                          <pre style={{ 
                            backgroundColor: '#f5f5f5', 
                            padding: '10px', 
                            borderRadius: '4px',
                            overflowX: 'auto'
                          }}>
                            {JSON.stringify(log.decrypted_features, null, 2)}
                          </pre>
                        </div>
                        <div style={{ marginTop: '10px' }}>
                          <strong>Decrypted Prediction:</strong> {log.decrypted_prediction}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p style={{ color: '#666' }}>Click on decrypt Logs to decrypt the encrypted log files.</p>
              )}
            </div>
          ) : (
            <p style={{ color: '#666' }}>Click on Fetch Logs to see encrypted logs available.</p>
          )}

          {logMessage && <p style={{ color: logMessage.includes('❌') ? 'red' : '#4CAF50' }}>{logMessage}</p>}
          <button 
            onClick={() => navigate('/')} 
            style={{ 
              padding: '10px 20px',
              backgroundColor: '#f44336',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              marginTop: '20px',
              fontSize: '16px'
            }}
          >
            Logout
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ 
      ...backgroundStyle,
      padding: '20px',
      backgroundColor: 'rgba(255, 255, 255, 0.9)'
    }}>
      <div style={{ 
        maxWidth: '1000px', 
        margin: '0 auto',
        backgroundColor: 'white',
        padding: '30px',
        borderRadius: '8px',
        boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)'
      }}>
        <h1 style={{ color: '#333', borderBottom: '1px solid #eee', paddingBottom: '10px' }}>🔍 Network Intrusion Detection</h1>
        <button 
          onClick={capturePacket} 
          disabled={loading}
          style={{
            padding: '10px 20px',
            backgroundColor: '#4CAF50',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            marginBottom: '20px',
            fontSize: '16px',
            
          }}
        >
          {loading ? 'Capturing...' : 'Capture Packet'}
        </button>

        {captureResult && (
          <div style={{ 
            marginBottom: '20px', 
            border: '1px solid #ddd', 
            padding: '20px', 
            borderRadius: '5px',
            backgroundColor: '#f9f9f9',
            
          }}>
            <h2 style={{ color: '#444', marginTop: 0 }}>Capture Result</h2>
            <div style={{ marginBottom: '10px' }}>
              <strong>Status:</strong> {captureResult.status || 'N/A'}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>Type:</strong> {captureResult.type || 'N/A'}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>Original Features:</strong>{' '}
              {captureResult.original_features ? (
                <pre style={{ 
                  backgroundColor: '#f5f5f5', 
                  padding: '10px', 
                  borderRadius: '4px',
                  overflowX: 'auto',
                  color: '#444'
                }}>
                  {JSON.stringify(captureResult.original_features, null, 2)}
                </pre>
              ) : (
                'N/A'
              )}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>Encrypted Features:</strong>{' '}
              {captureResult.encrypted_features ? (
                <pre style={{ 
                  backgroundColor: '#f5f5f5', 
                  padding: '10px', 
                  borderRadius: '4px',
                  overflowX: 'auto',
                  color: '#444'
                }}>
                  {JSON.stringify(captureResult.encrypted_features, null, 2)}
                </pre>
              ) : (
                'N/A'
              )}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>Encrypted Prediction:</strong> {captureResult.encrypted_prediction || 'N/A'}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>Encrypted AES Key:</strong> {captureResult.encrypted_aes_key || 'N/A'}
            </div>
            <div style={{ marginBottom: '10px', color: '#444' }}>
              <strong>IV:</strong> {captureResult.IV || 'N/A'}
            </div>
          </div>
        )}

        {status && <p style={{ 
          color: status.includes('⚠️') ? 'red' : '#4CAF50',
          fontWeight: 'bold',
          fontSize: '18px'
        }}>{status}</p>}
        <div style={{ marginTop: '20px' }}>
          <button 
            onClick={() => navigate('/manual-entry')} 
            style={{
              padding: '10px 20px',
              backgroundColor: '#2196F3',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              marginRight: '10px',
              fontSize: '16px'
            }}
          >
            Add Manually
          </button>
          <button 
            onClick={() => navigate('/')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#f44336',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '16px'
            }}
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

function ManualEntry({ user }) {
  const [inputData, setInputData] = useState({});
  const [classification, setClassification] = useState('');
  const [encryptedFeatures, setEncryptedFeatures] = useState('');
  const [encryptedPrediction, setEncryptedPrediction] = useState('');
  const [AES_Key, setAES_Key] = useState('');
  const [encryptedAESKey, setEncryptedAESKey] = useState('');
  const [IV, setIV] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleInputChange = (e) => {
    setInputData({ ...inputData, [e.target.name]: e.target.value });
  };

  const classifyIntrusion = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/user1/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(inputData)
      });
      const data = await response.json();
      setClassification(data.prediction_label);
      setEncryptedFeatures(JSON.stringify(data.encrypted_features));
      setEncryptedPrediction(data.encrypted_prediction);
      setAES_Key(data.AES_KEY);
      setEncryptedAESKey(data.encrypted_aes_key);
      setIV(data.IV);
    } catch (error) {
      console.error("Error classifying intrusion:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      ...backgroundStyle,
      padding: '20px',
      backgroundColor: 'rgba(255, 255, 255, 0.9)'
    }}>
      <div style={{ 
        maxWidth: '800px', 
        margin: '0 auto',
        backgroundColor: 'white',
        padding: '30px',
        borderRadius: '8px',
        boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)',
        
      }}>
        <h2 style={{ color: '#333', marginTop: 0 }}>Intrusion Classification</h2>
        <form onSubmit={classifyIntrusion}>
        <div style={{ 
          display: 'flex',
          flexDirection: 'column',
          gap: '1px',
          width: '100%',
          maxWidth: '800px',
          margin: '0 auto'
        }}>
          {[
            "Fwd Packet Length Mean",
            "Subflow Fwd Bytes",
            "Fwd Packet Length Max",
            "Total Length of Fwd Packets",
            "Flow IAT Max",
            "Flow Duration",
            "Total Length of Bwd Packets",
            "Subflow Bwd Bytes",
            "Bwd Packets/s",
            "Average Packet Size",
            "Avg Bwd Segment Size",
            "Flow Packets/s",
            "Destination Port",
            "Avg Fwd Segment Size",
            "Init_Win_bytes_backward",
            "Bwd Packet Length Max",
            "Fwd Packet Length Std",
            "Packet Length Mean",
            "Bwd Packet Length Std",
            "Fwd Header Length"
          ].map((field) => (
            <div key={field} style={{ marginBottom: '15px' }}>
              <label style={{ display: 'block', marginBottom: '5px',marginLeft: '200px', marginRight: '250px', fontWeight: 'bold', color: '#555' }}>{field}</label>
              <input 
                type="number" 
                name={field} 
                onChange={handleInputChange} 
                style={{ 
                  width: '100%', 
                  padding: '10px',
                  borderRadius: '4px',
                  border: '1px solid #ddd',
                  fontSize: '16px'
                }} 
              />
            </div>
          ))}
          <button 
            type="submit" 
            disabled={loading}
            style={{ 
              width: '100%', 
              padding: '12px',
              backgroundColor: loading ? '#999' : '#4CAF50',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              fontSize: '16px',
              cursor: 'pointer',
              marginTop: '10px'
            }}
          >
            {loading ? 'Classifying...' : 'Classify Intrusion'}
          </button>
        </div>  
        </form>
        {classification && (
          <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#f5f5f5', borderRadius: '4px' }}>
            <h3 style={{ marginTop: 0 }}>Results</h3>
            <p><strong>Prediction:</strong> {classification}</p>
            {encryptedFeatures && <p><strong>Encrypted Features:</strong> {encryptedFeatures}</p>}
            {encryptedPrediction && <p><strong>Encrypted Prediction:</strong> {encryptedPrediction}</p>}
            {AES_Key && <p><strong>Original AES Key:</strong> {AES_Key}</p>}
            {encryptedAESKey && <p><strong>Encrypted AES Key:</strong> {encryptedAESKey}</p>}
            {IV && <p><strong>IV:</strong> {IV}</p>}
          </div>
        )}
        <button 
          onClick={() => navigate('/dashboard')} 
          style={{ 
            padding: '10px 20px',
            backgroundColor: '#2196F3',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            marginTop: '20px',
            fontSize: '16px'
          }}
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<Login setUser={setUser} />} />
        <Route path="/dashboard" element={user ? <Dashboard user={user} /> : <Login setUser={setUser} />} />
        <Route
          path="/manual-entry"
          element={user ? <ManualEntry user={user} /> : <Login setUser={setUser} />}
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;