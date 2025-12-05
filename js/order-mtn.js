// Dedicated MTN order logic (separate from other operator pages)
document.addEventListener('DOMContentLoaded', function(){
  // No auth required - users can order directly

  const packages = {
    '1GB': 6.00,'2GB': 11.00,'3GB': 16.00,'4GB': 21.00,'5GB': 26.00,'6GB': 32.00,'8GB': 42.00,'10GB': 50.00,'15GB': 70.00,'20GB': 95.00,'25GB': 115.00,'30GB': 135.00,'40GB': 175.00,'50GB': 215.00
  };

  const sel = document.getElementById('packageSelectMTN');
  Object.keys(packages).forEach(k=>{
    const opt = document.createElement('option'); opt.value = k; opt.textContent = `${k} ------- GHS${packages[k].toFixed(2)}`; sel.appendChild(opt);
  });

  function isValidEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

  document.getElementById('mtnForm').addEventListener('submit', function(evt){
    evt.preventDefault();
    const msisdn = document.getElementById('msisdn').value.trim();
    const email = document.getElementById('email').value.trim();
    const pkg = document.getElementById('packageSelectMTN').value;
    if(!/^\d{10}$/.test(msisdn)){ alert('Please enter a valid 10 digit number'); return; }
    if(!isValidEmail(email)){ alert('Please enter a valid email'); return; }
    if(!pkg){ alert('Please select an MTN package'); return; }

    const price = packages[pkg];
    if(typeof price === 'undefined'){ alert('Price not available for selected package'); return; }

    const amountInPesewas = Math.round(price * 100);
    const publicKey = 'pk_live_91cfdef8bb6ab204ba3ec685224bbe3ff7aa0720';
    if(!window.PaystackPop){ alert('Payment library failed to load'); return; }

    const handler = PaystackPop.setup({
      key: publicKey,
      email: email,
      amount: amountInPesewas,
      currency: 'GHS',
      ref: 'MTN-' + Date.now(),
      metadata: { custom_fields:[{display_name:'Mobile',variable_name:'mobile',value:msisdn},{display_name:'Operator',variable_name:'operator',value:'MTN'},{display_name:'Package',variable_name:'package',value:pkg}] },
      callback: function(response){
        // Save order to localStorage
        const order = {
          id: response.reference,
          reference: response.reference,
          date: new Date().toISOString(),
          timestamp: Date.now(),
          email: email,
          phone: msisdn,
          mobile: msisdn,
          operator: 'MTN',
          package: pkg,
          amount: price,
          status: 'completed'
        };
        const orders = JSON.parse(localStorage.getItem('md_orders') || '[]');
        orders.push(order);
        localStorage.setItem('md_orders', JSON.stringify(orders));
        
        // Show success message
        if(typeof showToast === 'function'){
          showToast('✓ Order placed successfully! Your data bundle will be delivered shortly.', 5000);
        } else {
          alert('Order placed successfully! Your data bundle will be delivered shortly.');
        }
        
        // Redirect after displaying the message
        setTimeout(function(){
          try { window.location.href = 'index.html'; }
          catch(e){ window.location.href = 'index.html'; }
        }, 5500);
      },
      onClose: function(){ alert('Payment cancelled.'); }
    });

    handler.openIframe();
  });
});
