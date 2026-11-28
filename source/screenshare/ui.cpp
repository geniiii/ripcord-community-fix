// NOTE(Xelph): The screenshare window, in Qt like the rest of Ripcord. It is the only C++ in the plugin. It has no Q_OBJECT so it
//              needs no moc: every connection below is a lambda. It calls into the C side through the ss_api_* functions

#define NOMINMAX
#include <windows.h>
#include <dwmapi.h>
#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>
#include <QtWidgets/QApplication>
#include <QtWidgets/QBoxLayout>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDesktopWidget>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>

extern "C" {
unsigned char ss_api_in_voice(void);
unsigned char ss_api_active(void);
unsigned char ss_api_start(unsigned kind, void* window, const RECT* screen, const wchar_t* name, unsigned height, unsigned fps, unsigned quality);
void          ss_api_stop(void);
unsigned char ss_api_muted(void);
void          ss_api_toggle_mute(void);
void          ss_api_tick(void);
void          ss_api_status(wchar_t* out, unsigned count);
}

// NOTE(Xelph): The plugin is built with a static CRT and Qt's DLLs use the system one, and Qt frees what I allocate (an event it
//              takes ownership of, say). Both CRTs sit on the process heap, so allocating from it directly keeps them compatible
void* operator new(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}
void operator delete(void* pointer) noexcept {
    HeapFree(GetProcessHeap(), 0, pointer);
}
void operator delete(void* pointer, size_t) noexcept {
    HeapFree(GetProcessHeap(), 0, pointer);
}

namespace {

const unsigned kind_application = 1;
const unsigned kind_screen      = 2;
const unsigned heights[]        = {480, 720, 1080, 1440};
const unsigned frame_rates[]    = {30, 60};
const int      refresh_ms       = 500;

struct Source {
    unsigned kind;
    HWND     window;
    RECT     screen;
    wchar_t  name[160];
};

class ShareWindow : public QDialog {
   public:
    ShareWindow() : QDialog(nullptr, Qt::Dialog | Qt::WindowCloseButtonHint) {
        setWindowTitle("Screenshare");
        resize(460, 420);

        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(list = new QListWidget);

        QHBoxLayout* options = new QHBoxLayout;
        options->addWidget(height = new QComboBox);
        options->addWidget(fps = new QComboBox);
        options->addWidget(quality = new QComboBox);
        height->addItems(QStringList() << "480p" << "720p" << "1080p" << "1440p");
        fps->addItems(QStringList() << "30 fps" << "60 fps");
        quality->addItems(QStringList() << "Low quality" << "Balanced" << "High quality");
        height->setCurrentIndex(1);
        fps->setCurrentIndex(1);
        quality->setCurrentIndex(1);
        layout->addLayout(options);

        layout->addWidget(status = new QLabel);
        status->setWordWrap(true);

        QHBoxLayout* buttons = new QHBoxLayout;
        buttons->addWidget(go = new QPushButton("Go Live"));
        buttons->addWidget(mute = new QPushButton("Mute audio"));
        buttons->addWidget(refresh = new QPushButton("Refresh"));
        layout->addLayout(buttons);

        connect(go, &QPushButton::clicked, this, [this] { toggle_sharing(); });
        connect(mute, &QPushButton::clicked, this, [this] {
            ss_api_toggle_mute();
            update_state();
        });
        connect(refresh, &QPushButton::clicked, this, [this] { reload(); });
        connect(list, &QListWidget::itemSelectionChanged, this, [this] { update_state(); });
        connect(list, &QListWidget::itemDoubleClicked, this, [this] { toggle_sharing(); });

        qApp->installEventFilter(this);

        QTimer* timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this] { update_state(); });
        timer->start(refresh_ms);
        update_state();
    }

   protected:
    // NOTE(Xelph): A QShortcut wouldn't do: Qt only matches one while its parent widget is visible, and this window starts hidden.
    //              Watching key presses on the application sees them whichever Ripcord window has the focus
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (event->type() == QEvent::KeyPress) {
            QKeyEvent* key = static_cast<QKeyEvent*>(event);
            if (key->key() == Qt::Key_S && key->modifiers() == (Qt::ControlModifier | Qt::ShiftModifier) && !key->isAutoRepeat()) {
                toggle_window();
                return true;
            }
        }
        return QDialog::eventFilter(watched, event);
    }

   private:
    QListWidget*    list;
    QComboBox*      height;
    QComboBox*      fps;
    QComboBox*      quality;
    QLabel*         status;
    QPushButton*    go;
    QPushButton*    mute;
    QPushButton*    refresh;
    QVector<Source> sources;
    int             screen_count = 0;

    void add(const Source& source) {
        sources.append(source);
        list->addItem(QString::fromWCharArray(source.name));
    }

    void reload() {
        sources.clear();
        list->clear();
        screen_count = 0;

        struct Context {
            ShareWindow* self;
            HWND         own;
        } context = {this, (HWND) winId()};
        EnumWindows(
            [](HWND window, LPARAM param) -> BOOL {
                Context* context = (Context*) param;
                DWORD    cloaked = 0;
                DwmGetWindowAttribute(window, 14 /* DWMWA_CLOAKED */, &cloaked, sizeof cloaked);
                if (window == context->own || !IsWindowVisible(window) || GetWindow(window, GW_OWNER) || cloaked ||
                    (GetWindowLongW(window, GWL_EXSTYLE) & WS_EX_TOOLWINDOW)) {
                    return TRUE;
                }
                Source source = {kind_application, window};
                if (GetWindowTextW(window, source.name, 160) > 0) {
                    context->self->add(source);
                }
                return TRUE;
            },
            (LPARAM) &context);

        EnumDisplayMonitors(
            nullptr, nullptr,
            [](HMONITOR monitor, HDC, LPRECT rect, LPARAM param) -> BOOL {
                ShareWindow* self   = (ShareWindow*) param;
                Source       source = {kind_screen, nullptr, *rect};
                MONITORINFO  info   = {sizeof info};
                GetMonitorInfoW(monitor, &info);
                swprintf(source.name, 160, L"Screen %d%ls: %ldx%ld", ++self->screen_count, info.dwFlags & MONITORINFOF_PRIMARY ? L" (main)" : L"",
                         rect->right - rect->left, rect->bottom - rect->top);
                self->add(source);
                return TRUE;
            },
            (LPARAM) this);
    }

    void toggle_sharing() {
        if (ss_api_active()) {
            ss_api_stop();
        } else if (list->currentRow() >= 0) {
            const Source& source = sources[list->currentRow()];
            QApplication::setOverrideCursor(Qt::WaitCursor);
            ss_api_start(source.kind, source.window, &source.screen, source.name, heights[height->currentIndex()], frame_rates[fps->currentIndex()],
                         (unsigned) quality->currentIndex());
            QApplication::restoreOverrideCursor();
        }
        update_state();
    }

    void toggle_window() {
        if (isVisible()) {
            hide();
        } else if (ss_api_in_voice()) {
            reload();
            show();
            raise();
            activateWindow();
            move(QApplication::desktop()->availableGeometry(this).center() - rect().center());
        }
    }

    void update_state() {
        ss_api_tick();
        bool active = ss_api_active();
        go->setText(active ? "Stop sharing" : "Go Live");
        go->setEnabled(active || (list->currentRow() >= 0 && ss_api_in_voice()));
        mute->setVisible(active);
        mute->setText(ss_api_muted() ? "Unmute audio" : "Mute audio");
        for (QWidget* widget : QList<QWidget*>{list, height, fps, quality, refresh}) {
            widget->setEnabled(!active);
        }

        wchar_t text[256];
        ss_api_status(text, 256);
        status->setText(QString::fromWCharArray(text));
    }
};

// NOTE(Xelph): The window can't be built while the platform plugin is still loading, since QApplication doesn't exist yet. An
//              event posted now is delivered by the main loop once it does, on the GUI thread
class Starter : public QObject {
   public:
    static const QEvent::Type type = (QEvent::Type) (QEvent::User + 0x5353);

   protected:
    bool event(QEvent* event) override {
        if (event->type() == type) {
            new ShareWindow;
            return true;
        }
        return QObject::event(event);
    }
};

}  // namespace

extern "C" void ss_ui_init(void) {
    Starter* starter = new Starter;
    QCoreApplication::postEvent(starter, new QEvent(Starter::type));
}
