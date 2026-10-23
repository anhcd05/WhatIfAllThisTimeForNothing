function toggleCategory(element) {
    const content = element.nextElementSibling;
    const arrow = element.querySelector(".arrow");

    if (content.style.display === "block") {
        content.style.display = "none";
        arrow.classList.remove("down");
    } else {
        content.style.display = "block";
        arrow.classList.add("down");
    }
}

function showPopup(message, type) {
    const popup = document.getElementById('popup');
    popup.textContent = message;
    popup.className = 'popup ' + type;
    popup.style.display = 'block';
    setTimeout(() => {
        popup.style.display = 'none';
    }, 3000);
}


// Pls ignore the obviously visible flags bcs im lazy to encrypt
const flags = {
    "challenge_crypto_1": "CSG_FLAG{FleissnerGrill}",
    "challenge_forensic_1": "CSG_FLAG{Great_job_on_the_recovery!}",
    "challenge_network_1": "CSG_FLAG{!7 w4$ 34$y j06 w4$n'7 !7??}",
    "challenge_network_2": "CSG_FLAG{https://youtu.be/wE11GYxsE7M}",
    "challenge_network_3": "CSG_FLAG{IC3B3RG_IS_JUS7_TH3_T1P}",
    "challenge_rev_1": "CSG_FLAG{rock_crushes_scissors_water_erodes_rocks}",
    "challenge_rev_2": "CSG_FLAG{criminal_evidence_brought_to_LIGHT}",
    "challenge_rev_3": "CSG_FLAG{You_have_great_reversing_skills!}",
    "challenge_stego_1": "CSG_FLAG{M4rker_f4iled}",
    "challenge_stego_2": "CSG_FLAG{A_picture_is_worth_@_thousand_words}",
    "challenge_stego_3": "CSG_FLAG{Broaden_your_horizons_to_find_the_FLAG!35}",
    "challenge_osint_2": "CSG_FLAG{13249397}",
    "challenge_osint_3": "CSG_FLAG{OE-IOI:Hungary}",
    "challenge_osint_4": "CSG_FLAG{hiropi1991tanapon@gmail.com:enj0y555crypt0:h00r@y-g00d-j0b.com}",
    "challenge_misc_1": "CSG_FLAG{h4sh_browns_with_onions_4_bre4kf4st}",
    "challenge_misc_2": "CSG_FLAG{Helen Beatrix Potter}"
    };


function checkFlag(challengeId) {
    const input = document.getElementById(challengeId).value.trim();
    const correctFlag = flags[challengeId];

    if (!correctFlag) {
        showPopup("Error: Unknown challenge ID", "error");
        return;
    }

    if (input === correctFlag) {
        showPopup("Correct! 🎉", "success");
    } else if (input === "") {
        showPopup("Please input a flag.", "error");
    } else {
        showPopup("Incorrect. Try again!", "error");
    }
}
