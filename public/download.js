// /download page — waitlist form + success modal.
// Loaded as an external file because the site CSP blocks inline scripts.
(function () {
  var form     = document.getElementById('waitlist-form');
  if (!form) return; // page rendered without the waitlist section — bail.

  var emailEl  = document.getElementById('wl-email');
  var nameEl   = document.getElementById('wl-name');
  var roleEl   = document.getElementById('wl-role');
  var submit   = document.getElementById('wl-submit');
  var errEl    = document.getElementById('wl-error');
  var modal    = document.getElementById('wl-modal');
  var mClose   = document.getElementById('wl-modal-close');
  var mDismiss = document.getElementById('wl-modal-dismiss');
  var mTitle   = document.getElementById('wl-modal-title');
  var mBody    = document.getElementById('wl-modal-body');
  var mIcon    = document.getElementById('wl-modal-icon');
  var mPos     = document.getElementById('wl-modal-position');

  function escapeHtml(s) {
    return String(s).replace(/[<>&"']/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function showModal(state) {
    mTitle.textContent = state.title;
    mBody.innerHTML = state.body;
    mIcon.textContent = state.icon;
    if (state.position) {
      mPos.textContent = state.position;
      mPos.style.display = 'inline-block';
    } else {
      mPos.style.display = 'none';
    }
    modal.classList.add('show');
  }
  function hideModal() { modal.classList.remove('show'); }

  [mClose, mDismiss].forEach(function (b) {
    if (b) b.addEventListener('click', hideModal);
  });
  if (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target === modal) hideModal();
    });
  }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') hideModal();
  });

  function setError(msg) { if (errEl) errEl.textContent = msg || ''; }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    setError('');

    var email = (emailEl.value || '').trim();
    if (!email) {
      setError('Please enter your email.');
      emailEl.focus();
      return;
    }
    var emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      setError('That email looks off. Double-check it?');
      emailEl.focus();
      return;
    }

    submit.disabled = true;
    submit.textContent = 'Joining…';

    try {
      var res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          name:  (nameEl.value || '').trim(),
          role:  (roleEl.value || '').trim()
        })
      });

      var data = {};
      try { data = await res.json(); } catch (_) {}

      if (res.ok && data.ok) {
        if (data.alreadyJoined) {
          showModal({
            title: "You're already on the list.",
            body:  "We've got you. We'll send the build link to <strong>" + escapeHtml(email) + "</strong> when it's ready.",
            icon:  '✓'
          });
        } else {
          var pos = (data.position && typeof data.position === 'number')
            ? '#' + data.position + ' in line'
            : null;
          showModal({
            title: "You're on the list.",
            body:  "We'll email <strong>" + escapeHtml(email) + "</strong> the moment the BurnLink CLI build is ready.",
            icon:  '✓',
            position: pos
          });
        }
        form.reset();
      } else {
        setError((data && data.error) || 'Something went wrong. Please try again.');
      }
    } catch (err) {
      setError('Network error. Check your connection and try again.');
    } finally {
      submit.disabled = false;
      submit.textContent = 'Join the Waitlist';
    }
  });
})();
