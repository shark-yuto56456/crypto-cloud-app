<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>クライアントサイド暗号化ストレージ</title>
    <style>
        body { font-family: sans-serif; background: #f4f7f6; padding: 40px; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h1 { font-size: 22px; text-align: center; color: #2c3e50; }
        label { font-weight: bold; display: block; margin-top: 15px; }
        input, textarea, button { width: 100%; padding: 10px; margin-top: 5px; box-sizing: border-box; border-radius: 6px; border: 1px solid #ccc; }
        textarea { height: 100px; }
        button { background: #3498db; color: white; border: none; font-weight: bold; cursor: pointer; margin-top: 15px; }
        button:hover { background: #2980b9; }
        .result-box { margin-top: 20px; padding: 12px; background: #e8f4f8; border-left: 4px solid #3498db; display: none; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body>
<div class="container">
    <h1>暗号化クラウドストレージ</h1>
    <p style="font-size:12px; color:gray; text-align:center;">データは送信前にPC側で暗号化されます。パスワードはサーバーに送信されません。</p>

    <h3>【保存】データを暗号化してクラウドへ</h3>
    <label>データ保存用ID</label>
    <input type="text" id="save-id" placeholder="my-secret-key-1">
    <label>暗号化パスフレーズ</label>
    <input type="password" id="save-pw" placeholder="パスワードを入力">
    <label>秘密のデータ</label>
    <textarea id="save-text" placeholder="ここに保存したいテキストを入力"></textarea>
    <button onclick="encryptAndSave()">暗号化してクラウドに保存</button>

    <hr style="margin:30px 0; border:0; border-top:1px solid #eee;">

    <h3>【復号】クラウドからデータを取得</h3>
    <label>データ保存用ID</label>
    <input type="text" id="get-id" placeholder="my-secret-key-1">
    <label>復号パスフレーズ</label>
    <input type="password" id="get-pw" placeholder="パスワードを入力">
    <button style="background:#2ecc71;" onclick="loadAndDecrypt()">取得してPC側で復号</button>

    <div id="result" class="result-box"></div>
</div>

<script>
    // パスワードから暗号鍵を誘導する関数(PBKDF2)
    async function deriveKey(passphrase, salt) {
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
        return window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
            baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
    }

    // データの暗号化と送信
    async function encryptAndSave() {
        const id = document.getElementById('save-id').value.trim();
        const pw = document.getElementById('save-pw').value;
        const text = document.getElementById('save-text').value;
        if (!id || !pw || !text) return alert("すべて入力してください");

        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(pw, salt);
        
        const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(text));
        
        // Salt + IV + 暗号データを1つに結合してBase64化
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);
        const base64Data = btoa(String.fromCharCode(...combined));

        const res = await fetch('/api/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id, encryptedData: base64Data })
        });
        if (res.ok) alert("暗号化データをクラウドに送信しました！");
    }

    // データの取得と復号
    async function loadAndDecrypt() {
        const id = document.getElementById('get-id').value.trim();
        const pw = document.getElementById('get-pw').value;
        if (!id || !pw) return alert("IDとパスワードを入力してください");

        const res = await fetch('/api/get/' + id);
        if (!res.ok) return alert("データが見つかりません");
        const json = await res.ok ? await res.json() : {};

        const binaryStr = atob(json.encryptedData);
        const combined = new Uint8Array(binaryStr.length);
        for(let i=0; i<binaryStr.length; i++) combined[i] = binaryStr.charCodeAt(i);

        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const encData = combined.slice(28);

        try {
            const key = await deriveKey(pw, salt);
            const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encData);
            
            const resultBox = document.getElementById('result');
            resultBox.innerText = "復号されたデータ:\n" + new TextDecoder().decode(decrypted);
            resultBox.style.display = 'block';
        } catch(e) {
            alert("復号に失敗しました。パスフレーズが違うか、データが改ざんされています。");
        }
    }
</script>
</body>
</html>
