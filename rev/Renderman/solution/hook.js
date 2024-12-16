console.log("Hooked!");
var i = 0;

Java.perform(function x() {
    console.log("Inside Java.perform()!");
    var Main_class = Java.use("io.github.spookie.Main");

    Main_class.triggerJumpscare.implementation = function() {
        this.cam.value.near.value = 0.0;
        this.cam.value.update();
        this.state.value = i;
        this.shuffleFlagChars();

        console.log("Current state: " + this.state.value);
    };

    var listenForStateChange = function() {
        recv('changeState', function(message) {
            console.log("Changing state...");
            i++;
            listenForStateChange();
        });
    };

    listenForStateChange();
});