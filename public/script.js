const socket = io();

const contactList = document.getElementById("contact-list");
const chatBox = document.getElementById("chat-box");
const currentChat = document.getElementById("current-chat");
const contactSearchInput = document.getElementById("contact-search");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");

let activeContact = null;

// Initial dummy contact list
const contacts = [];
fetch("/friends", {
  method: "GET",
})
  .then((res) => {
    return res.json();
  })
  .then((data) => {
    data.forEach((friend) => {
      contacts.push(friend);
    });
    displayContacts(contacts);
  })
  .catch((err) => {
    console.error("Error fetching contacts:", err);
  });

// Function to populate contacts
function displayContacts(filteredContacts) {
  contactList.innerHTML = ""; // Clear the list
  filteredContacts.forEach((contact) => {
    const li = document.createElement("li");
    li.textContent = contact;

    li.addEventListener("click", () => {
      activeContact = contact;
      currentChat.textContent = `Chat with ${contact}`;
      chatBox.innerHTML = ""; // Clear chat box
    });

    contactList.appendChild(li);
  });
}

// Add new contact if not found
function addNewContact(contactName) {
  console.log("Add new contact");
  fetch("/friends", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contactName }),
  })
    .then((res) => {
      console.log(res);
      if (res.status === 200) {
        console.log("Contact added successfully");
        contacts.push(contactName);
        displayContacts(contacts);
      } else {
        alert(res.statusText);
      }
    })
    .catch((err) => {
      alert(err);
    });
}

// Add search and add-contact functionality
contactSearchInput.addEventListener("input", (event) => {
  const searchTerm = event.target.value.toLowerCase();
  const filteredContacts = contacts.filter((contact) =>
    contact.toLowerCase().includes(searchTerm)
  );

  // Display filtered contacts
  displayContacts(filteredContacts);

  // Check if no results match and prompt to add the contact
  if (searchTerm && filteredContacts.length === 0) {
    const addContactOption = document.createElement("li");
    addContactOption.textContent = `Add "${event.target.value}"`;
    addContactOption.style.color = "blue";
    addContactOption.style.cursor = "pointer";

    addContactOption.addEventListener("click", () => {
      console.log("clicked");
      addNewContact(event.target.value);
    });

    contactList.appendChild(addContactOption);
  }
});

// Send message
sendBtn.addEventListener("click", () => {
  const message = messageInput.value.trim();
  if (message && activeContact) {
    // Emit private message to the server
    console.log(activeContact);
    socket.emit("message", { toUser: activeContact, message });

    // Display sent message in the chat
    const msg = document.createElement("p");
    msg.textContent = `${message}`;
    msg.className = "sentMessage";
    chatBox.appendChild(msg);

    messageInput.value = "";
  }
});

// Receive private messages
socket.on("message", (message) => {
  const msg = document.createElement("p");
  msg.textContent = `${message}`;
  msg.className = "recMessage";
  chatBox.appendChild(msg);
});
