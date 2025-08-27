/* eslint-disable linebreak-style */
const API_KEY = '039d20cd-7782-4cf1-9ec5-a54373449df0';
const NO_IMG = 'https://upload.wikimedia.org/wikipedia/commons/a/ac/No_image_available.svg';

// const app = Vue.createApp({
//   data() {
//     return {
//       dark_mode: false, // Default to light mode
//     };
//   },
//   watch: {
//     dark_mode(val) {
//       if (val) {
//         document.body.classList.add('darkMode'); // Add dark mode class
//         localStorage.setItem('theme', 'dark'); // Save preference
//       } else {
//         document.body.classList.remove('darkMode'); // Remove dark mode class
//         localStorage.setItem('theme', 'light'); // Save preference
//       }
//     },
//   },
//   mounted() {
//     // Load the saved theme preference
//     const savedTheme = localStorage.getItem('theme');
//     if (savedTheme === 'dark') {
//       this.dark_mode = true;
//     }
//   },
// }).mount('#app');

Vue.createApp({
  data() {
    return {
      artworks: [],
      likedArtworks: [],
      likedArtworkIds: [],
      loading: true,
      dark_mode: false,
      signedInUser: null,
      profilePic: '',
      defaultPic: '../stylesheets/images/profilePic.jpg',
      noImg: NO_IMG,
      newUsername: '',
      newPassword: '',
      searchQuery: '',
      lastSearchTerm: '', // for displaying searching for: x
      modalVisible: false,
      modalArtwork: null,
      csrfToken: '' // Store the CSRF token here
    };
  },
  mounted: async function() {
    this.fetchCsrfToken(); // Fetch the CSRF token when the component is mounted

    //managing login state
    this.signedInUser = localStorage.getItem('user_id');

    const currentPage = window.location.pathname;

    if (!this.signedInUser && !currentPage.includes('login.html') && !currentPage.includes('SignUp.html') && !currentPage.includes('Home.html')) {
      window.location.href = '/login.html';
      return;
    }

    //dark/light mode
    this.dark_mode = localStorage.getItem('theme') === 'dark';
    this.toggleBody(this.dark_mode);

    // Profile pic (load from storage first)
    const storedPic = localStorage.getItem('profile_pic');
    this.profilePic = storedPic || this.defaultPic;

    //nav bar visibility
    const authLinks = document.querySelectorAll('.auth-only');
    const guestLinks = document.querySelectorAll('.guest-only');
    const guestandAuth = document.querySelectorAll('.guestandAuth');
    authLinks.forEach(link => link.style.display = this.signedInUser ? 'inline-block' : 'none');
    guestLinks.forEach(link => link.style.display = this.signedInUser ? 'none' : 'inline-block');
    guestandAuth.forEach(link => link.style.display = 'inline-block');

    //managing session
    if (this.signedInUser) {
      this.fetchProfilePic();
      this.fetchLikedArtworks();
      this.fetchArtworks();
    }

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') this.modalVisible = false;
    });

  },

  watch: {
    dark_mode(val) {
      this.toggleBody(val);
      localStorage.setItem('theme', val ? 'dark' : 'light');
    }
  },

  methods: {
    async fetchCsrfToken() {
      try {
        const response = await fetch('/csrf-token', {
          method: 'GET',
          credentials: 'include' // Ensure cookies are sent with the request
        });
        const data = await response.json();
        this.csrfToken = data.csrf_token; // Save the CSRF token
      } catch (err) {
        console.error('Failed to fetch CSRF token:', err);
      }
    },

    //light/dark mode
    toggleBody(on){
      document.body.classList.toggle('darkMode', on);
    },

    //fetches artwork
    async fetchArtworks() {
      this.loading = true;
      try {
        const res = await fetch(
          `https://api.harvardartmuseums.org/object?apikey=${API_KEY}&size=50&hasimage=1&sort=random&fields=primaryimageurl,title,people,objectnumber,dated`
        );
        const { records = [] } = await res.json();
        this.artworks = records.filter(r => r.primaryimageurl).slice(0, 30);
      } catch (err) {
        console.error('Error fetching artworks:', err);
      } finally {
        this.loading = false;
      }
    },

    openImg(url) {
      window.open(url, "_blank", "noopener");
    },

    //fetched liked art work
    async fetchLikedArtworks() {
      const userId = this.signedInUser;
      if (!userId) {
        console.warn("No user ID found. Cannot fetch likes.");
        return;
      }
      this.loading = true;
      try {
        const res = await fetch(`http://localhost:8000/likes/${userId}`, {
          credentials: 'include'
        });
        const data = await res.json();
        this.likedArtworks = data;
        this.likedArtworkIds = data.map(art => art.id);
      } catch (err) {
        console.error("Error loading liked artworks:", err);
      }
    },

    //allows to add and remove liked art
    async toggleLike(art) {
      const liked = this.likedArtworkIds.includes(art.id);
      const payload = {
        user_id: this.signedInUser,
        artwork_id: art.id
      };

      try {
        const res = await fetch(`http://localhost:8000/${liked ? 'unlike' : 'like'}`, {
          method: liked ? 'DELETE' : 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.csrfToken // Include the CSRF token
          },
          body: JSON.stringify(payload),
          credentials: 'include'
        });

        const data = await res.json();
        if (data.message) {
          if (liked) {
            this.likedArtworkIds = this.likedArtworkIds.filter(id => id !== art.id);
            this.likedArtworks = this.likedArtworks.filter(a => a.id !== art.id);
            alert('Artwork removed from your collection.');
          } else {
            this.likedArtworkIds.push(art.id);
            alert('Artwork liked and added to your collection!');
          }
        } else {
          alert(data.error || 'Unexpected error');
        }
      } catch (err) {
        console.error('Toggle like failed:', err);
      }
    },

    //logic for opening modal
    async openModal(art) {
      const artworkId = art?.id;
      if (!artworkId) {
        console.warn("Missing artwork ID, modal not opened.");
        return;
      }

      this.modalVisible = true;
      this.modalArtwork = { ...art, id: String(art.id) };

      try {
        const res = await fetch(`https://api.harvardartmuseums.org/object/${artworkId}?apikey=${API_KEY}`);
        const data = await res.json();

        this.modalArtwork = {
          ...this.modalArtwork,
          ...data,
          id: String(data.id)
        };

      } catch (err) {
        console.error("Error loading full artwork details:", err);
        alert("Failed to load full details for this artwork.");
        this.modalVisible = false;
      }
    },


    //logout lopgic
    async logout() {
      localStorage.removeItem('user_id');
      localStorage.removeItem('profile_pic');
      this.signedInUser = null;
      window.location.href = '/login.html';
    },


    //changing profile pic
    async uploadPic(event) {
      const file = event.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async () => {
        const base64Image = reader.result;
        try {
          const res = await fetch('http://localhost:8000/uploadProfilePic', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': this.csrfToken // Include the CSRF token
            },
            body: JSON.stringify({
              user_id: this.signedInUser,
              image: base64Image
            }),
            credentials: 'include'
          });

          const data = await res.json();
          if (data.success) {
            await this.fetchProfilePic();
          } else {
            console.error('Upload failed:', data.error);
          }
        } catch (err) {
          console.error('Upload error:', err);
        }
      };
      reader.readAsDataURL(file);
    },

    //fetchs pfp for user
    async fetchProfilePic() {
      try {
        const url = `http://localhost:8000/profilePic/${this.signedInUser}`;
        const response = await fetch(url);
        if (response.ok) {
          const fullUrl = `${url}?t=${Date.now()}`;
          this.profilePic = fullUrl;
          localStorage.setItem('profile_pic', fullUrl);
        } else {
          this.profilePic = this.defaultPic;
          localStorage.removeItem('profile_pic');
        }
      } catch (err) {
        console.error('Error fetching profile picture:', err);
        this.profilePic = this.defaultPic;
        localStorage.removeItem('profile_pic');
      }
    },

    //logic for updating user and pass
    async updateSettings() {
      const payload = {
        user_id: this.signedInUser,
        new_username: this.newUsername,
        new_password: this.newPassword
      };

      try {
        const res = await fetch('http://localhost:8000/updateUser', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.csrfToken // Include the CSRF token
          },
          body: JSON.stringify(payload),
          credentials: 'include' // Ensure cookies are sent with the request
        });

        const data = await res.json();
        if (data.success) {
          alert('Settings updated successfully!');
          this.newUsername = '';
          this.newPassword = '';
        } else {
          alert(data.error || 'Update failed.');
        }
      } catch (err) {
        console.error('Update error:', err);
        alert('Server error. Try again later.');
      }
    },

    //searcing logic
    async performSearch(){
      const searched = this.searchQuery.trim();
      if (!searched){
        this.lastSearchTerm = '';
        await this.fetchArtworks();
        return;
      }
      this.loading = true;
      try {
        const url = `https://api.harvardartmuseums.org/object?apikey=${API_KEY}` +
                    `&size=50&hasimage=1&keyword=${encodeURIComponent(this.searchQuery)}&sort=rank`;

        const res = await fetch(url);
        const data = await res.json();

        this.lastSearchTerm = searched; // change searching for
        this.artworks = (data.records || [])
        .filter(r => r.primaryimageurl)
        .slice(0, 30)
        .map(r => ({
          ...r,
          id: String(r.id)
        }));

        this.searchQuery = ''; // clear serach box

      } catch(err){
        console.error('Search failed', err);
        alert('Search failed, try again later');
      } finally {
        this.loading = false;
      }
    }

  }
}).mount('#app');

const signUpApp = Vue.createApp({
      data() {
        return {
          username: '',
          email: '',
          password: '',
          submitting: false,
          error: null,
          success: null,
          passwordStrength: '',
          csrfToken: '' // Store the CSRF token here
        };
      },
      methods: {
        async fetchCsrfToken() {
          try {
            const response = await fetch('/csrf-token', {
              method: 'GET',
              credentials: 'include' // Ensure cookies are sent with the request
            });
            const data = await response.json();
            this.csrfToken = data.csrf_token; // Save the CSRF token
          } catch (err) {
            console.error('Failed to fetch CSRF token:', err);
          }
        },
        async handleSignUp() {
          this.error = null;
          this.success = null;

          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(this.email)) {
            this.error = 'Please enter a valid email address.';
            return;
          }
          if (this.password.length < 6) {
            this.error = 'Password must be at least 6 characters.';
            return;
          }

          this.submitting = true;
          try {
            const res = await fetch('http://localhost:8000/register', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.csrfToken // Include the CSRF token
              },
              body: JSON.stringify({
                username: this.username,
                email: this.email,
                password: this.password
              })
            });
            const data = await res.json();

            if (res.ok && data.success) {
              this.success = 'Account created! Redirecting…';
              setTimeout(() => (window.location.href = '/explore.html'), 1000);
            } else {
              this.error = data.error || 'Sign-up failed. Please try again.';
            }
          } catch (err) {
            this.error = `Network error: ${err.message}`;
          } finally {
            this.submitting = false;
          }
        },
        checkPasswordStrength() {
          const password = this.password;
          const strengthIndicator = document.getElementById('password-strength');

          if (password.length >= 8 && password.match(/[0-9]/) && password.match(/[@$!%*?&#]/)) {
            this.passwordStrength = 'High';
            strengthIndicator.style.color = 'green';
          } else if (password.length >= 8 && (password.match(/[0-9]/) || password.match(/[@$!%*?&#]/))) {
            this.passwordStrength = 'Medium';
            strengthIndicator.style.color = 'orange';
          } else {
            this.passwordStrength = 'Weak';
            strengthIndicator.style.color = 'red';
          }
        },
      },
      computed: {
        isPasswordValid() {
          return (
            this.password.length >= 8 &&
            this.password.match(/[0-9]/) &&
            this.password.match(/[@$!%*?&#]/)
          );
        },
      },
      mounted() {
        this.fetchCsrfToken(); // Fetch the CSRF token when the component is mounted
      },
    }).mount('#signupApp');

const loginApp = Vue.createApp({
  data() {
    return {
      username: '', // username OR email
      password: '',
      submitting: false,
      error: null,
      success: null,
      csrfToken: '' // Store the CSRF token here
    };
  },
  methods: {
    async fetchCsrfToken() {
      try {
        const response = await fetch('/csrf-token', {
          method: 'GET',
          credentials: 'include' // Ensure cookies are sent with the request
        });
        const data = await response.json();
        this.csrfToken = data.csrf_token; // Save the CSRF token
      } catch (err) {
        console.error('Failed to fetch CSRF token:', err);
      }
    },
    async handleLogin() {
      this.error = null;
      this.success = null;

      if (!this.username || !this.password) {
        this.error = 'Both fields are required.';
        return;
      }

      this.submitting = true;
      try {
        const res = await fetch('http://localhost:8000/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.csrfToken // Include the CSRF token in the headers
          },
          body: JSON.stringify({
            username: this.username,
            password: this.password,
          }),
          credentials: 'include', // Ensure cookies are sent with the request
        });

        const data = await res.json();

        if (res.ok && data.success) {
          localStorage.setItem('user_id', data.user_id);
          this.success = 'Welcome back! Redirecting…';
          setTimeout(() => (window.location.href = '/explore.html'), 1000);
        } else {
          this.error = data.error || 'Login failed. Check your credentials.';
        }
      } catch (err) {
        this.error = `Network error: ${err.message}`;
      } finally {
        this.submitting = false;
      }
    },
  },
  mounted() {
    this.fetchCsrfToken(); // Fetch the CSRF token when the component is mounted
  },
}).mount('#loginApp');

function handleCredentialResponse(response) {
  console.log("Encoded JWT ID token: " + response.credential);

  fetch('/api/auth/google', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: response.credential }),
  })
    .then((res) => res.json())
    .then((data) => {
      if (data.success) {
        localStorage.setItem('user_id', data.user_id);
        console.log('User authenticated:', data.user);
        // Redirect or perform further actions
        window.location.href = '/Explore.html';
      } else {
        console.error('Authentication failed:', data.error);
      }
    })
    .catch((err) => console.error('Error:', err));
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

const adminApp = Vue.createApp({
  data() {
    return {
      signedInUser: null, // Stores the signed-in user
      dark_mode: false, // Dark mode toggle
      users: [], // List of all users
      newUser: {
        username: '',
        email: '',
        password: '',
        role: 'user', // Default role is 'user'
      },
      editingUser: null, // User being edited
      submitting: false, // To handle loading state
      error: null, // Error message
      success: null, // Success message
      csrfToken: '' // Store the CSRF token here
    };
  },
  computed: {
    isAdmin() {
      return this.signedInUser && this.signedInUser.role === 'admin';
    },
  },
  methods: {
    async fetchCsrfToken() {
      try {
        const response = await fetch('/csrf-token', {
          method: 'GET',
          credentials: 'include' // Ensure cookies are sent with the request
        });
        const data = await response.json();
        this.csrfToken = data.csrf_token; // Save the CSRF token
      } catch (err) {
        console.error('Failed to fetch CSRF token:', err);
      }
    },

    // Fetch all users from the backend
    async fetchUsers() {
      this.error = null;
      this.success = null;
      try {
        const res = await fetch('/admin/users', { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          this.users = data.users; // Assuming the backend returns { success: true, users: [...] }
        } else {
          const errorData = await res.json();
          this.error = errorData.error || 'Failed to fetch users.';
        }
      } catch (err) {
        console.error('Error fetching users:', err);
        this.error = 'Network error. Please try again later.';
      }
    },

    // Add a new user
    async addUser() {
      this.error = null;
      this.success = null;
      this.submitting = true;
      try {
        const res = await fetch('/admin/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.newUser),
          credentials: 'include',
        });
        if (res.ok) {
          this.success = 'User added successfully!';
          this.fetchUsers(); // Refresh the user list
          this.newUser = { username: '', email: '', password: '', role: 'user' }; // Reset form
        } else {
          const errorData = await res.json();
          this.error = errorData.error || 'Failed to add user.';
        }
      } catch (err) {
        console.error('Error adding user:', err);
        this.error = 'Network error. Please try again later.';
      } finally {
        this.submitting = false;
      }
    },

    // Delete a user
    async deleteUser(userId) {
      if (!confirm('Are you sure you want to delete this user?')) return;

      this.error = null;
      this.success = null;
      try {
        const res = await fetch(`/admin/users/${userId}`, {
          method: 'DELETE',
          credentials: 'include',
        });
        if (res.ok) {
          this.success = 'User deleted successfully!';
          this.fetchUsers(); // Refresh the user list
        } else {
          const errorData = await res.json();
          this.error = errorData.error || 'Failed to delete user.';
        }
      } catch (err) {
        console.error('Error deleting user:', err);
        this.error = 'Network error. Please try again later.';
      }
    },

    // Edit a user
    editUser(user) {
      this.editingUser = { ...user }; // Clone the user object to avoid modifying the original
    },

    // Save edited user details
    async saveUser() {
      this.error = null;
      this.success = null;
      this.submitting = true;
      try {
        const res = await fetch(`/admin/users/${this.editingUser.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.editingUser),
          credentials: 'include',
        });
        if (res.ok) {
          this.success = 'User updated successfully!';
          this.fetchUsers(); // Refresh the user list
          this.editingUser = null; // Exit edit mode
        } else {
          const errorData = await res.json();
          this.error = errorData.error || 'Failed to update user.';
        }
      } catch (err) {
        console.error('Error updating user:', err);
        this.error = 'Network error. Please try again later.';
      } finally {
        this.submitting = false;
      }
    },

    // Logout the admin
    logout() {
      this.signedInUser = null;
      sessionStorage.clear(); // Clear session storage
      window.location.href = '/login.html'; // Redirect to login page
    },
  },
  mounted() {
    this.fetchCsrfToken(); // Fetch the CSRF token when the component is mounted

    // Load the signed-in user from session storage
    const user = JSON.parse(sessionStorage.getItem('signedInUser'));
    if (user) {
      this.signedInUser = user;
      this.fetchUsers(); // Fetch users when the app is mounted
    } else {
      // Redirect non-logged-in users to the login page
      window.location.href = '/login.html';
    }

    // Dark mode setup
    this.dark_mode = localStorage.getItem('theme') === 'dark';
    this.toggleBody(this.dark_mode);
  },
  watch: {
    dark_mode(val) {
      this.toggleBody(val);
      localStorage.setItem('theme', val ? 'dark' : 'light');
    },
  },
}).mount('#adminApp');
