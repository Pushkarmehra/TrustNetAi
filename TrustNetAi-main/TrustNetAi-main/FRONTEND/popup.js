const API_BASE = 'http://localhost:8000';

// DOM Elements
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const loading = document.getElementById('loading');
const loadingText = document.getElementById('loadingText');
const result = document.getElementById('result');

// Text elements
const textInput = document.getElementById('textInput');
const verifyTextBtn = document.getElementById('verifyTextBtn');

// Image elements
const imageUpload = document.getElementById('imageUpload');
const imageInput = document.getElementById('imageInput');
const imageUrlInput = document.getElementById('imageUrlInput');
const verifyImageBtn = document.getElementById('verifyImageBtn');
let selectedImage = null;

// Video elements
const videoInput = document.getElementById('videoInput');
const verifyVideoBtn = document.getElementById('verifyVideoBtn');

// Tab Switching
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(tc => tc.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(`${tabName}-tab`).classList.add('active');
        
        hideResult();
    });
});

// Check Backend Connection
async function checkConnection() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        if (data.status === 'healthy') {
            statusDot.classList.add('connected');
            statusText.textContent = `✅ Connected - Forensic Analyzer Active`;
        }
    } catch (error) {
        statusDot.classList.remove('connected');
        statusText.textContent = '❌ Backend Offline - Start server';
        console.error('Connection error:', error);
    }
}

// Text Verification
verifyTextBtn.addEventListener('click', async () => {
    const text = textInput.value.trim();
    
    if (!text || text.length < 20) {
        alert('⚠️ Please enter at least 20 characters for accurate analysis');
        return;
    }
    
    showLoading('Analyzing text patterns...');
    
    try {
        const response = await fetch(`${API_BASE}/verify/text`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Verification failed');
        }
        
        const data = await response.json();
        console.log('Text verification response:', data);
        
        if (data.success) {
            displayResult(data.verification, 'text');
        } else {
            throw new Error('Verification failed');
        }
    } catch (error) {
        hideLoading();
        alert('❌ Error: ' + error.message);
        console.error('Text verification error:', error);
    }
});

// Image Upload Handling
imageUpload.addEventListener('click', () => imageInput.click());

imageUpload.addEventListener('dragover', (e) => {
    e.preventDefault();
    imageUpload.classList.add('drag-over');
});

imageUpload.addEventListener('dragleave', () => {
    imageUpload.classList.remove('drag-over');
});

imageUpload.addEventListener('drop', (e) => {
    e.preventDefault();
    imageUpload.classList.remove('drag-over');
    
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) {
        handleImageFile(file);
    }
});

imageInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        handleImageFile(file);
    }
});

function handleImageFile(file) {
    selectedImage = file;
    imageUrlInput.value = '';
    imageUpload.innerHTML = `
        <div class="upload-icon">✅</div>
        <div>Image selected: ${file.name}</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
            Click Verify to analyze
        </div>
    `;
    verifyImageBtn.disabled = false;
}

// Image Verification
verifyImageBtn.addEventListener('click', async () => {
    const imageUrl = imageUrlInput.value.trim();

    if (selectedImage) {
        showLoading('Analyzing uploaded image + metadata...');
        try {
            const formData = new FormData();
            formData.append('file', selectedImage);
            
            const response = await fetch(`${API_BASE}/verify/image`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Verification failed');
            }
            
            const data = await response.json();
            console.log('Image verification response:', data);
            
            if (data.success) {
                displayResult(data.verification, 'image');
            } else {
                throw new Error('Verification failed');
            }
        } catch (error) {
            hideLoading();
            alert('❌ Error: ' + error.message);
            console.error('Image verification error:', error);
        }
    } else if (imageUrl) {
        showLoading('Fetching and analyzing image from URL...');
        try {
            const response = await fetch(`${API_BASE}/verify/image-from-url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: imageUrl })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Verification failed');
            }

            const data = await response.json();
            console.log('Image URL verification response:', data);

            if (data.success) {
                displayResult(data.verification, 'image');
            } else {
                throw new Error('Verification failed');
            }
        } catch (error) {
            hideLoading();
            alert('❌ Error: ' + error.message);
            console.error('Image URL verification error:', error);
        }
    } else {
        alert('⚠️ Please select an image file or paste an image URL');
    }
});

// Clear other input when one is used
imageUrlInput.addEventListener('input', () => {
    if (imageUrlInput.value.trim() !== '') {
        selectedImage = null;
        imageUpload.innerHTML = `
            <div class="upload-icon">🖼️</div>
            <div>Click or drag image here</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
                JPG, PNG, WEBP (max 10MB)
            </div>
        `;
        verifyImageBtn.disabled = false;
    }
});

// Video Verification
verifyVideoBtn.addEventListener('click', async () => {
    const videoInfo = videoInput.value.trim();
    
    if (!videoInfo || videoInfo.length < 10) {
        alert('⚠️ Please provide video URL or description');
        return;
    }
    
    showLoading('Analyzing video for deepfakes...');
    
    try {
        const response = await fetch(`${API_BASE}/verify/video`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                video_description: videoInfo 
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Verification failed');
        }
        
        const data = await response.json();
        console.log('Video verification response:', data);
        
        if (data.success) {
            displayResult(data.verification, 'video');
        } else {
            throw new Error('Verification failed');
        }
    } catch (error) {
        hideLoading();
        alert('❌ Error: ' + error.message);
        console.error('Video verification error:', error);
    }
});

// Display Functions
function showLoading(message = 'Analyzing content...') {
    loadingText.textContent = message;
    loading.style.display = 'block';
    result.style.display = 'none';
}

function hideLoading() {
    loading.style.display = 'none';
}

function hideResult() {
    result.style.display = 'none';
}

function displayResult(verification, mediaType) {
    console.log(`Displaying ${mediaType} result:`, verification);
    hideLoading();

    const riskLevel = (verification.risk_level || 'medium').toLowerCase();
    result.className = 'result ' + riskLevel;

    const emojiMap = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '⚠️',
        'low': '✓',
        'minimal': '✅'
    };

    document.getElementById('resultEmoji').textContent = emojiMap[riskLevel] || '🔍';
    document.getElementById('resultVerdict').textContent = verification.verdict || 'Analysis Complete';
    document.getElementById('resultScore').textContent = `Risk Score: ${verification.risk_score || 0}%`;

    document.getElementById('resultType').textContent = mediaType.toUpperCase();
    document.getElementById('resultGenerated').textContent =
        verification.risk_score > 50 ? '🤖 LIKELY YES' : '👤 LIKELY NO';
    document.getElementById('resultModel').textContent = 'Forensic Analysis';
    document.getElementById('resultConfidence').textContent = `${verification.risk_score || 0}%`;

    const riskBadge = document.getElementById('resultRisk');
    riskBadge.textContent = (verification.risk_level || 'MEDIUM').toUpperCase();
    riskBadge.className = 'risk-badge risk-' + riskLevel;

    document.getElementById('resultModelsUsed').textContent = 'Forensic Analyzer';
    document.getElementById('resultConsensus').textContent =
        `${verification.flag_count || 0} flags detected`;

    let reportText = `🔬 FORENSIC ANALYSIS REPORT (${mediaType.toUpperCase()})\n`;
    reportText += "=".repeat(50) + "\n\n";
    reportText += `📊 SUMMARY:\n`;
    reportText += `  Risk Score: ${verification.risk_score}%\n`;
    reportText += `  Verdict: ${verification.verdict}\n`;
    reportText += `  Risk Level: ${verification.risk_level}\n`;
    reportText += `  Total Flags: ${verification.flag_count || 0}\n`;

    if (mediaType === 'image') {
        reportText += `  Critical: ${verification.critical_flags || 0} | High: ${verification.high_flags || 0}\n`;
        reportText += `  Dimensions: ${verification.dimensions || 'Unknown'}\n`;
        reportText += `  Format: ${verification.format || 'Unknown'}\n`;
        reportText += `  File Size: ${(verification.file_size / 1024).toFixed(1)} KB\n\n`;
    }

    if (verification.flags && verification.flags.length > 0) {
        reportText += "🚩 FORENSIC FLAGS DETECTED:\n";
        reportText += "=".repeat(50) + "\n\n";

        const flagsBySeverity = verification.flags.reduce((acc, flag) => {
            if (!acc[flag.severity]) {
                acc[flag.severity] = [];
            }
            acc[flag.severity].push(flag);
            return acc;
        }, {});

        for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
            if (flagsBySeverity[severity]) {
                reportText += `🚨 ${severity} FLAGS:\n`;
                flagsBySeverity[severity].forEach((flag, i) => {
                    reportText += `  ${i + 1}. [${flag.category}] ${flag.description}\n`;
                    reportText += `     Evidence: ${flag.evidence}\n`;
                    reportText += `     Impact: +${flag.score_impact} points\n\n`;
                });
            }
        }
    }

    if (mediaType === 'image' && verification.texture_analysis) {
        const texture = verification.texture_analysis;
        reportText += "🔬 TEXTURE ANALYSIS:\n";
        reportText += "=".repeat(50) + "\n";
        if (texture.laplacian_variance !== undefined) {
            reportText += `  Laplacian Variance: ${texture.laplacian_variance.toFixed(6)}\n`;
        }
        if (texture.gradient_mean !== undefined) {
            reportText += `  Gradient Mean: ${texture.gradient_mean.toFixed(6)}\n`;
        }
        if (texture.high_freq_energy !== undefined) {
            reportText += `  High-Freq Energy: ${texture.high_freq_energy.toFixed(2)}\n`;
        }
        reportText += "\n";
    }

    if (mediaType === 'image' && verification.exif_data && Object.keys(verification.exif_data).length > 0) {
        reportText += "📷 EXIF METADATA FOUND:\n";
        reportText += "=".repeat(50) + "\n";
        const exifKeys = Object.keys(verification.exif_data);
        reportText += `  Total EXIF fields: ${exifKeys.length}\n`;
        reportText += `  (View full EXIF in browser console)\n\n`;
    } else if (mediaType === 'image') {
        reportText += "❌ NO EXIF METADATA FOUND\n";
        reportText += "   This is highly suspicious for real camera photos.\n\n";
    }

    if (verification.gemini_validation) {
        reportText += "🤖 GEMINI VISUAL VALIDATION:\n";
        reportText += "=".repeat(50) + "\n";
        reportText += verification.gemini_validation + "\n\n";
    }

    reportText += "=".repeat(50) + "\n";
    reportText += "⚠️  DISCLAIMER:\n";
    reportText += "This analysis provides strong indicators but is not 100% definitive proof.\n";

    document.getElementById('resultReasoning').textContent = reportText;

    result.style.display = 'block';
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkConnection();
    setInterval(checkConnection, 30000); // Check every 30 seconds
});
