import kivy.uix.button as kb
from kivy.app import App
from kivy.uix.widget import Widget


class Button_Widget(Widget):

    def __init__(self, **kwargs):
        super(Button_Widget, self).__init__(**kwargs)
        btn1 = kb.Button(text='Click to collect data')
        btn1.bind(on_press=self.callback)
        self.add_widget(btn1)

    def callback(self, instance):
        print('Collecting Data...')


class ButtonApp(App):

    def build(self):
        return Button_Widget()


if __name__ == "__main__":
    ButtonApp().run()

