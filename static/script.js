function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function openTab(tabName) {
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    
    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(btn => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
    });
    event.target.classList.add('active');
    event.target.setAttribute('aria-selected', 'true');
}

document.getElementById('generate-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').innerHTML = '<div class="result-header"><span>Password</span><span>Strength</span><span>Entropy</span><span>Action</span></div>';
    document.getElementById('download-btn').style.display = 'none';
    
    const response = await fetch('/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    document.getElementById('loading').style.display = 'none';
    
    if (response.ok) {
        const result = await response.json();
        const resultsDiv = document.getElementById('results');
        result.passwords.forEach((p, index) => {
            const strengthClass = p.strength >= 80 ? 'strength-green' : p.strength >= 50 ? 'strength-yellow' : 'strength-red';
            const item = document.createElement('div');
            item.classList.add('result-item');
            item.innerHTML = `
                <span>${escapeHTML(p.password)}</span>
                <span class="${strengthClass}">${p.strength}%</span>
                <span class="entropy">${p.entropy}</span>
                <span><button class="copy-btn" data-password="${p.password.replace(/"/g, '&quot;')}">Copy</button></span>
            `;
            item.style.animationDelay = `${index * 0.1}s`;
            resultsDiv.appendChild(item);
        });
        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const password = btn.getAttribute('data-password');
                copyToClipboard(password, btn);
            });
        });
        document.getElementById('download-btn').style.display = 'block';
        document.getElementById('download-btn').onclick = () => download(result.passwords, data.output_format);
    } else {
        const error = await response.json();
        alert(error.error);
    }
});

document.getElementById('check-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    document.getElementById('loading-check').style.display = 'block';
    document.getElementById('check-results').innerHTML = '';
    
    const response = await fetch('/check_pwned', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    document.getElementById('loading-check').style.display = 'none';
    
    const result = await response.json();
    const resultsDiv = document.getElementById('check-results');

    const isGreen = result.status === 'Not Found';
    const colorClass = isGreen ? 'pwned-result-green' : 'pwned-result-red';

    let html = `
        <div class="pwned-result ${colorClass}">
            <p><strong>Status:</strong> ${escapeHTML(result.status)}</p>
    `;
    if (result.sha1) {
        html += `<p><strong>SHA1:</strong> ${escapeHTML(result.sha1)}</p>`;
    }
    if (result.breach_count !== undefined) {
        html += `<p><strong>Breach Count:</strong> ${escapeHTML(result.breach_count)}</p>`;
    }
    html += `
            <p><strong>Message:</strong> ${escapeHTML(result.message)}</p>
        </div>
    `;

    resultsDiv.innerHTML = html;
});

document.querySelector('.toggle-password').addEventListener('click', () => {
    const passwordInput = document.getElementById('password');
    const icon = document.querySelector('.toggle-password i');
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
});

async function download(passwords, format) {
    const response = await fetch('/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passwords, format })
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `passwords.${format}`;
    a.click();
    URL.revokeObjectURL(url);
}

function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        button.textContent = 'Copied!';
        button.disabled = true;
        setTimeout(() => {
            button.textContent = 'Copy';
            button.disabled = false;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
        alert('Failed to copy password.');
    });
}