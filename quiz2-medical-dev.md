6.858 Quiz 2 Review
===================

Medical Device Security
-----------------------

FDA standards: Semmelweis e.g. `=>` Should wash hands

Defirbillator:

  - 2003: Implanted defibrillator use WiFi. What could
    possibly go wrong?
  - Inside: battery, radio, hermetically sealed	

Why wireless?

  - Old way: Inject a needle into arm to twist dial, risk of infection :(

**Q:** What are security risks of wireless?

  - Unsafe practices - implementation errors.
  - Manufacturer and User Facility Device Experience (MAUDE) database
     * Cause of death: buffer overflow in infusion pump.
     * Error detected, but brought to safe mode, turn off pump.
     * Patient died after increase in brain pressure because
       no pump, because of buffer overflow.

#### Human factors and software

Why unique?

500+ deaths

E.g. User interface for delivering dosage to patients did not properly indicate
whether it expected hours or minutes as input (hh:mm:ss). Led to order of
magnitude error: 20 min vs. the intended 20 hrs.

#### Managerial issues

Medical devices also need to take software updates.

E.g. McAffee classified DLL as malicious, quarantines,
messed up hospital services.

E.g. hospitals using Windows XP:
  - There are no more security updates from Microsoft for XP, but still new medical products shipping Windows XP.


#### FDA Cybersecurity Guidance

What is expected to be seen from manufacturers? How they
have thought through the security problems / risks /
mitigation strategies / residual risks?


#### Adversary stuff

Defibrillator & Implants

This section of the notes refers to the discussion of attacks on implanted defibrillators from Kevin Fu's lecture. In one example he gave, the implanted devices are wirelessly programmed with another device called a "wand", which uses a proprietary (non-public, non-standardized) protocol. Also, the wand transmits (and the device listens) on specially licensed EM spectrum (e.g. not WiFI or bluetooth). The next two lines describe the surgical process by which the defibrillator is implanted in the patient.

  - Device programmed w/ wand, speaking proprietary protocol
    over specially licensed spectrum. (good idea w.r.t.
    security?)
  - Patient awake but numbed and sedated
  - Six people weave electrodes through blood vessel....

  - Patient given a base station, looks like AP, speaks proprietary RF to implant, 
    data sent via Internet to healthcare company

  - Communication between device and programmer: no crypto / auth, data sent in plaintext
  - Device stores:	Patient name, DOB, make & model, serial no., more...

  - ???????? Use a software radio (USRP/GNU Radio Software)

**Q:** Can you wirelessly induce a fatal heart rhythm  
**A:** Yes. Device emitted 500V shock in 1 msec. E.g. get kicked in chest by horse.

Devices fixed through software updates?

#### Healthcare Providers

Screenshot of "Hospitals Stuck with Windows XP": 600 Service Pack 0 Windows XP devices in the hospital!

Average time to infection for healthcare devices:
  - 12 days w/o protection
  - 1 year w/ antivirus

#### Vendors are a common source of infection

USB drive is a common vector for infection.

#### Medical device signatures over download

"Click here to download software update"

  - Website appears to contain malware
  - Chrome: Safe web browsing service detected "ventilator" malware

"Drug Compounder" example:

  - Runs Windows XP embedded
  - **FDA expects manufacturers to keep SW up to date**
  - **Manufacturers claim cannot update because of FDA**
      * _double you tea f?_

#### How significant intentional malicious SW malfunctions?

E.g. 1: Chicago 1982: Somebody inserts cyanide into Tylenol
E.g. 2: Somebody posted flashing images on epillepsy support group website.


#### Why do you trust sensors?

E.g. smartphones. Batteryless sensors demo. Running on an MSP430. uC believes
anything coming from ADC to uC. Possible to do something related to resonant
freq. of wire there?

Inject interference into the baseband

  - Hard to filter in the analog
  - `=>` Higher quality audio w/ interference than microphone

Send a signal that matches resonant frequency of the wire.

Treat circuit as unintentional demodulator

  - Can use high frequency signal to trick uC into thinking
  - there is a low frequency signal due to knowing interrupt
    frequency of uC and related properties.

Cardiac devices vulnerable to baseband EMI

  - Insert intentional EM interference in baseband

Send pulsed sinewave to trick defibrilator into thinking heart beating correctly

  - ????? Works in vitro
  - Hard to replicate in a body or saline solution

Any defenses?

  - Send an extra pacing pulse right after a beat
    * a real heart shouldn't send a response

#### Detecting malware at power outlets

Embedded system `<-->` WattsUpDoc `<-->` Power outlet

#### Bigger problems than security?

**Q:** True or false: Hackers breaking into medical devices is
the biggest risk at the moment.

**A:** False. Wide scale unavailability of patient care and integrity of
medical sensors are more important.

Security cannot be bolted on

  - E.g. MRI on windows 95
  - E.g. Pacemaker programmer running on OS/2

Check gmail on medical devices, etc.

Run pandora on medical machine.

Keep clinical workflow predictable.

