import { StrictMode, Component } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div style={{ background: '#060d1a', color: '#ef4444', padding: 40, fontFamily: 'monospace', minHeight: '100vh' }}>
          <h2 style={{ color: '#f97316', marginBottom: 16 }}>⚠ React Render Error</h2>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 13, color: '#fca5a5' }}>
            {this.state.error.toString()}
          </pre>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 11, color: '#94a3b8', marginTop: 16 }}>
            {this.state.error.stack}
          </pre>
          <button onClick={() => this.setState({ error: null })}
            style={{ marginTop: 24, padding: '8px 20px', background: '#1e4060', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
)
