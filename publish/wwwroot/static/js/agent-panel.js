/**
 * BareMetalWeb Agent Panel — floating chat widget for natural language interaction.
 * Sends user messages to /api/agent/chat and displays responses.
 * Supports entity queries, data operations, and system commands.
 */
(function () {
  'use strict';

  const ENDPOINT = '/api/agent/chat';

  // State
  let isOpen = false;
  let messages = [];

  // Build floating button
  const fab = document.createElement('button');
  fab.id = 'bm-agent-fab';
  fab.innerHTML = '&#x1F916;'; // robot emoji
  fab.title = 'Agent Panel';
  Object.assign(fab.style, {
    position: 'fixed', bottom: '24px', right: '24px', zIndex: '10000',
    width: '56px', height: '56px', borderRadius: '50%', border: 'none',
    background: 'var(--bs-primary, #0d6efd)', color: '#fff', fontSize: '24px',
    cursor: 'pointer', boxShadow: '0 4px 12px rgba(0,0,0,.3)', transition: 'transform .2s',
  });
  fab.addEventListener('mouseenter', () => fab.style.transform = 'scale(1.1)');
  fab.addEventListener('mouseleave', () => fab.style.transform = 'scale(1)');

  // Build chat panel
  const panel = document.createElement('div');
  panel.id = 'bm-agent-panel';
  Object.assign(panel.style, {
    position: 'fixed', bottom: '90px', right: '24px', zIndex: '10001',
    width: '380px', maxHeight: '520px', borderRadius: '12px',
    background: 'var(--bs-body-bg, #fff)', border: '1px solid var(--bs-border-color, #dee2e6)',
    boxShadow: '0 8px 32px rgba(0,0,0,.2)', display: 'none',
    flexDirection: 'column', overflow: 'hidden', fontFamily: 'inherit',
  });

  // Header
  const header = document.createElement('div');
  Object.assign(header.style, {
    padding: '12px 16px', background: 'var(--bs-primary, #0d6efd)', color: '#fff',
    fontWeight: '600', fontSize: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
  });
  header.innerHTML = '<span>&#x1F916; Agent</span>';
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '×';
  Object.assign(closeBtn.style, {
    background: 'none', border: 'none', color: '#fff', fontSize: '20px', cursor: 'pointer', lineHeight: '1',
  });
  closeBtn.onclick = () => toggle(false);
  header.appendChild(closeBtn);

  // Message area
  const msgArea = document.createElement('div');
  msgArea.id = 'bm-agent-messages';
  Object.assign(msgArea.style, {
    flex: '1', overflowY: 'auto', padding: '12px', minHeight: '300px', maxHeight: '380px',
  });

  // Input area
  const inputArea = document.createElement('div');
  Object.assign(inputArea.style, {
    display: 'flex', borderTop: '1px solid var(--bs-border-color, #dee2e6)', padding: '8px',
  });
  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'Ask anything...';
  Object.assign(input.style, {
    flex: '1', border: '1px solid var(--bs-border-color, #dee2e6)', borderRadius: '6px',
    padding: '8px 12px', fontSize: '13px', outline: 'none',
    background: 'var(--bs-body-bg, #fff)', color: 'var(--bs-body-color, #212529)',
  });
  const sendBtn = document.createElement('button');
  sendBtn.textContent = 'Send';
  Object.assign(sendBtn.style, {
    marginLeft: '8px', padding: '8px 16px', border: 'none', borderRadius: '6px',
    background: 'var(--bs-primary, #0d6efd)', color: '#fff', cursor: 'pointer', fontSize: '13px',
  });

  panel.appendChild(header);
  panel.appendChild(msgArea);
  inputArea.appendChild(input);
  inputArea.appendChild(sendBtn);
  panel.appendChild(inputArea);

  // Toggle
  function toggle(open) {
    isOpen = open !== undefined ? open : !isOpen;
    panel.style.display = isOpen ? 'flex' : 'none';
    if (isOpen) {
      input.focus();
      if (messages.length === 0) addMessage('assistant', 'Hello! I can help you query data, manage entities, and perform system operations. What would you like to do?');
    }
  }

  function addMessage(role, text) {
    messages.push({ role, text });
    const bubble = document.createElement('div');
    Object.assign(bubble.style, {
      marginBottom: '8px', padding: '8px 12px', borderRadius: '8px', fontSize: '13px',
      maxWidth: '90%', wordBreak: 'break-word', lineHeight: '1.4',
    });
    if (role === 'user') {
      Object.assign(bubble.style, {
        marginLeft: 'auto', background: 'var(--bs-primary, #0d6efd)', color: '#fff',
      });
    } else {
      Object.assign(bubble.style, {
        background: 'var(--bs-secondary-bg, #e9ecef)', color: 'var(--bs-body-color, #212529)',
      });
    }
    bubble.textContent = text;
    msgArea.appendChild(bubble);
    msgArea.scrollTop = msgArea.scrollHeight;
  }

  async function send() {
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    addMessage('user', text);
    sendBtn.disabled = true;

    try {
      const resp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, history: messages.slice(-10).map(m => ({ role: m.role, content: m.text })) }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      addMessage('assistant', data.reply || data.error || 'No response');
    } catch (err) {
      addMessage('assistant', 'Error: ' + err.message);
    } finally {
      sendBtn.disabled = false;
    }
  }

  sendBtn.onclick = send;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
  fab.onclick = () => toggle();

  // Mount
  document.body.appendChild(fab);
  document.body.appendChild(panel);
})();
