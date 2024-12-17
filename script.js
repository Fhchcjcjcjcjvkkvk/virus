// Client-side code (script.js)
const socket = io();

// Reference to the messages div
const messagesDiv = document.getElementById('messages');
const chatInput = document.getElementById('chat-input');

// Listen for incoming messages from the server
socket.on('message', (msg) => {
  const messageElement = document.createElement('div');
  messageElement.textContent = msg;
  messagesDiv.appendChild(messageElement);
  messagesDiv.scrollTop = messagesDiv.scrollHeight; // Auto-scroll to the latest message
});

// Send message to the server when user presses Enter
chatInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && chatInput.value.trim() !== '') {
    const message = chatInput.value.trim();
    socket.emit('chatMessage', message);  // Send message to the server
    chatInput.value = ''; // Clear input field
  }
});
