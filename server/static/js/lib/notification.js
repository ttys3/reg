function Notification(Title, Message, Icon) {
    let obj = {};
    obj.progress = 0;
    obj.fadeTime = 1000;
    obj.fadeTicks = 50;
    obj.fadeInterval = 0;
    obj.opacity = 1;
    obj.time = 2;
    obj.ticks = 100;
    obj.element = null;
    obj.progress = null;
    obj.progressPos = 0;
    obj.progressIncrement = 0;
    obj.Show = function () {
        obj.element = document.createElement('div');
        obj.element.className = "Notification " + Icon;

        let content = document.createElement('div');
        content.className = "Content";
        content.innerHTML = "" +
            "<h1>"+Title+"</h1>"+
            "<label>" + Message + "</label>" +
            "";
        obj.element.appendChild(content);
        const progressDiv = document.createElement('div');
        progressDiv.className = 'ProgressDiv';
        obj.progress = document.createElement('div');
        progressDiv.appendChild(obj.progress);
        obj.element.appendChild(progressDiv);
        obj.progressIncrement = 100 / obj.ticks;
        document.querySelector('#notifications').appendChild(obj.element);
        obj.StartWait();
    };
    obj.StartWait = function () {
        // return;
        if (obj.progressPos >= 100) {
            obj.fadeInterval = 1;
            obj.FadeTick();
            return;
        }
        setTimeout(obj.Tick, obj.time);
    };
    obj.Clear = function () {
        obj.opacity = 0;
        obj.progressPos = 100;
        obj.element.remove();
        obj = null;
        return;
    };
    obj.FadeTick = function () {
        obj.opacity = ((obj.opacity * 100) - obj.fadeInterval) / 100;
        if (obj.opacity <= 0) {
            obj.element.remove();
            obj = null;
            return;
        }
        obj.element.style.opacity = obj.opacity;
        setTimeout(obj.FadeTick, (obj.fadeTime / obj.fadeTicks));
    };
    obj.Tick = function () {
        obj.progressPos += obj.progressIncrement;
        obj.progress.style.width = obj.progressPos + "%";
        obj.StartWait();
    };
    obj.Show();
    return obj;
}