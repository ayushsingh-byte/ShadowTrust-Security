// storefront cart widget (minified in prod)
async function addToCart(id){ await fetch('/api/cart',{method:'POST',body:JSON.stringify({id})}); }
document.querySelectorAll('.buy').forEach(b=>b.onclick=()=>addToCart(b.dataset.id));
