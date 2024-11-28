// Selecting DOM elements
const progress = document.querySelector('.progress');
const statusText = document.querySelector('.status');

let uploadPercentage = 0;

// Function to simulate the uploading process
function simulateUpload() {
  if (uploadPercentage < 100) {
    // Increment progress randomly between 2% and 10%
    uploadPercentage += Math.floor(Math.random() * 9) + 2;
    if (uploadPercentage > 100) uploadPercentage = 100; // Cap at 100%

    // Update progress bar and status text
    progress.style.width = uploadPercentage + '%';
    statusText.textContent = `Uploading... ${uploadPercentage}%`;

    // Continue simulation
    setTimeout(simulateUpload, 200);
  } else {
    // Final message once upload is complete
    statusText.textContent = 'Upload Complete. Virus Deployed!';
    statusText.style.color = 'red';
    progress.style.background = 'red';
    progress.style.boxShadow = '0 0 10px red, 0 0 20px red';
  }
}

// Start the simulation
simulateUpload();
