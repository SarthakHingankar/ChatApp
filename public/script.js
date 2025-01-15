const socket = io();

const contactList = document.getElementById("contact-list");
const chatBox = document.getElementById("chat-box");
const currentChat = document.getElementById("current-chat");
const contactSearchInput = document.getElementById("contact-search");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");

let activeContact = null;

const contacts = [];
const unread = [];
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
    displayContacts(contacts, unread);
  })
  .catch((err) => {
    console.error("Error fetching contacts:", err);
  });

function displayMessage(sender) {
  fetch("/data", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  })
    .then((res) => {
      if (res) {
        return res.json();
      }
    })
    .then((res) => {
      const messages = res[sender];
      messages.forEach((message) => {
        const msg = document.createElement("p");
        msg.textContent = `${message}`;
        msg.className = "recMessage";
        chatBox.appendChild(msg);
      });
    });
}
function clearDatabase(sender) {
  fetch("/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sender }),
  });
}

// Function to populate contacts
function displayContacts(filteredContacts, unreadMessages) {
  contactList.innerHTML = ""; // Clear the list

  filteredContacts.forEach((contact) => {
    const li = document.createElement("li");
    li.textContent = contact;

    // Add a blue dot if there are unread messages for this contact
    if (unreadMessages.includes(contact)) {
      const dot = document.createElement("span");
      dot.style.width = "10px";
      dot.style.height = "10px";
      dot.style.borderRadius = "50%";
      dot.style.backgroundColor = "blue";
      dot.style.display = "inline-block";
      dot.style.marginLeft = "10px";
      li.appendChild(dot);
    }

    li.addEventListener("click", () => {
      activeContact = contact;
      currentChat.textContent = `Chat with ${contact}`;
      chatBox.innerHTML = ""; // Clear chat box
      displayMessage(contact);
      clearDatabase(contact);

      // Mark the contact as read (remove from unreadMessages array)
      const index = unreadMessages.indexOf(contact);
      if (index !== -1) {
        unreadMessages.splice(index, 1);
        displayContacts(filteredContacts, unreadMessages); // Update the list
      }
    });

    contactList.appendChild(li);
  });
}

// Add new contact if not found
function addNewContact(contactName) {
  fetch("/friends", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contactName }),
  })
    .then((res) => {
      if (res.status === 200) {
        contacts.push(contactName);
        displayContacts(contacts, unread);
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
  displayContacts(filteredContacts, unread);

  // Check if no results match and prompt to add the contact
  if (searchTerm && filteredContacts.length === 0) {
    const addContactOption = document.createElement("li");
    addContactOption.textContent = `Add "${event.target.value}"`;
    addContactOption.style.color = "blue";
    addContactOption.style.cursor = "pointer";

    addContactOption.addEventListener("click", () => {
      addNewContact(event.target.value);
    });

    contactList.appendChild(addContactOption);
  }
});

// Send message
sendBtn.addEventListener("click", () => {
  const message = messageInput.value.trim();
  if (message && activeContact) {
    socket.emit("message", { reciever: activeContact, message });

    // Display sent message in the chat
    const msg = document.createElement("p");
    msg.textContent = `${message}`;
    msg.className = "sentMessage";
    chatBox.appendChild(msg);

    messageInput.value = "";
  }
});

// Receive private messages
socket.on("message", (sender, message) => {
  if (activeContact == sender) {
    const msg = document.createElement("p");
    msg.textContent = `${message}`;
    msg.className = "recMessage";
    chatBox.appendChild(msg);
    clearDatabase(sender);
  } else {
    unread.push(sender);
    displayContacts(contacts, unread);
  }
});
