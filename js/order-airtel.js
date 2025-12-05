// Dedicated AirtelTigo order logic (separate file)
document.addEventListener('DOMContentLoaded', function(){
  // No auth required - users can order directly

  const packages = {
    '1GB': 6.00,'2GB': 11.00,'3GB': 15.00,'4GB': 20.00,'5GB': 25.00,'6GB': 30.00,'7GB': 35.00,'8GB': 40.00,'10GB': 50.00,'20GB': 75.00,'30GB': 85.00,'40GB': 120.00,'50GB': 130.00,'100GB':230.00
  };

  const sel = document.getElementById('packageSelectAirtelTigo');
  Object.keys(packages).forEach(k=>{
    const opt = document.createElement('option'); opt.value = k; opt.textContent = `${k} ------- GHS${packages[k].toFixed(2)}`; sel.appendChild(opt);
  });

  function isValidEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

  document.getElementById('airtelForm').addEventListener('submit', function(evt){
    evt.preventDefault();
    const msisdn = document.getElementById('msisdn').value.trim();
    const email = document.getElementById('email').value.trim();
    const pkg = document.getElementById('packageSelectAirtelTigo').value;
    if(!/^\d{10}$/.test(msisdn)){ alert('Please enter a valid 10 digit number'); return; }
    if(!isValidEmail(email)){ alert('Please enter a valid email'); return; }
    if(!pkg){ alert('Please select an AirtelTigo package'); return; }

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
      ref: 'AIR-' + Date.now(),
      metadata: { custom_fields:[{display_name:'Mobile',variable_name:'mobile',value:msisdn},{display_name:'Operator',variable_name:'operator',value:'AirtelTigo'},{display_name:'Package',variable_name:'package',value:pkg}] },
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
          operator: 'AirtelTigo',
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
