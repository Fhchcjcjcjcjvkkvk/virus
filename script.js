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

// Send message to the server when the user types something and presses Enter
chatInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && chatInput.value.trim() !== '') {
    socket.emit('chatMessage', chatInput.value);
    chatInput.value = ''; // Clear input field
  }
});
