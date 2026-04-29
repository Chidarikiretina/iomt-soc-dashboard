/**
 * useSOCSocket — WebSocket hook for IoMT SOC live data
 * Connects to the FastAPI backend and streams real-time classifications.
 */
import { useState, useEffect, useRef, useCallback } from 'react';

const _BASE   = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8005';
const WS_URL  = _BASE.replace(/^http/, 'ws') + '/ws';   // http→ws, https→wss
const API_URL = _BASE;

export function useSOCSocket({ onTraffic, onAlert } = {}) {
  const ws            = useRef(null);
  const [connected,   setConnected]   = useState(false);
  const [liveRunning, setLiveRunning] = useState(false);
  const [backendUp,   setBackendUp]   = useState(false);
  const reconnectRef  = useRef(null);

  const connect = useCallback(() => {
    if (ws.current?.readyState === WebSocket.OPEN) return;

    const socket = new WebSocket(WS_URL);

    socket.onopen = () => {
      setConnected(true);
      setBackendUp(true);
      clearTimeout(reconnectRef.current);
      console.log('[SOC] WebSocket connected');
      // Auto-start the stream on connect
      socket.send(JSON.stringify({ cmd: 'start', interval: 0.8 }));
      setLiveRunning(true);
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'status') {
          setLiveRunning(data.running);
          return;
        }

        if (data.type === 'traffic') {
          onTraffic?.(data);

          // Raise an alert if the model detected an attack
          if (data.is_attack && data.severity) {
            onAlert?.({
              id:           Date.now(),
              type:         data.prediction,
              trueCategory: data.true_category ?? null,
              severity:     data.severity,
              device:       data.device,
              sourceIP:     data.src_ip,
              destIP:       data.dst_ip,
              confidence:   data.confidence,
              anomalyScore: data.anomaly_score,
              time:         new Date().toLocaleTimeString(),
              status:       'active',
              mitre:        getMitre(data.prediction),
            });
          }
        }
      } catch (e) {
        console.warn('[SOC] parse error', e);
      }
    };

    socket.onclose = () => {
      setConnected(false);
      setLiveRunning(false);
      // Auto-reconnect after 3 s
      reconnectRef.current = setTimeout(connect, 3000);
    };

    socket.onerror = () => {
      setBackendUp(false);
      socket.close();
    };

    ws.current = socket;
  }, [onTraffic, onAlert]);

  // Auto-connect on mount
  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectRef.current);
      ws.current?.close();
    };
  }, [connect]);

  // Control helpers
  const startLive = useCallback((interval = 0.8) => {
    ws.current?.send(JSON.stringify({ cmd: 'start', interval }));
    setLiveRunning(true);
  }, []);

  const stopLive = useCallback(() => {
    ws.current?.send(JSON.stringify({ cmd: 'stop' }));
    setLiveRunning(false);
  }, []);

  const resetStats = useCallback(async () => {
    await fetch(`${API_URL}/api/reset`, { method: 'POST' }).catch(() => {});
  }, []);

  return { connected, liveRunning, backendUp, startLive, stopLive, resetStats };
}

// Map prediction class → MITRE ATT&CK
function getMitre(prediction) {
  const map = {
    DDoS:     { tactic: 'Impact',           techniqueId: 'T1498' },
    DoS:      { tactic: 'Impact',           techniqueId: 'T1499' },
    Recon:    { tactic: 'Reconnaissance',   techniqueId: 'T1595' },
    MQTT:     { tactic: 'Execution',        techniqueId: 'T1059' },
    Spoofing: { tactic: 'Defense Evasion',  techniqueId: 'T1036' },
  };
  return map[prediction] || { tactic: 'Unknown', techniqueId: 'N/A' };
}
