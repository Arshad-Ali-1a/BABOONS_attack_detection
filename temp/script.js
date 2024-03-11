let counter = 1

setInterval(() => {
    document.getElementById('count').textContent = counter++;
}, 500)