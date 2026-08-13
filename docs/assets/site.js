const menuButton = document.querySelector(".menu-button");
const navigation = document.querySelector(".site-nav");

menuButton?.addEventListener("click", () => {
  const expanded = menuButton.getAttribute("aria-expanded") === "true";
  menuButton.setAttribute("aria-expanded", String(!expanded));
  navigation?.classList.toggle("is-open", !expanded);
});

navigation?.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    menuButton?.setAttribute("aria-expanded", "false");
    navigation.classList.remove("is-open");
  });
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const command = button.getAttribute("data-copy");
    if (!command || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(command);
      const label = button.querySelector(".copy-label");
      if (!label) return;
      label.textContent = "Copied";
      window.setTimeout(() => { label.textContent = "Copy"; }, 1600);
    } catch {
      // The command remains selectable when clipboard access is unavailable.
    }
  });
});
