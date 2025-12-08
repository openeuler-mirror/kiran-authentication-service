#include <QApplication>
#include <QFileInfo>
#include <QTranslator>

#include "config.h"
#include "gen-code-dialog.h"

int main(int argc, char *argv[])
{
    auto argv0 = QFileInfo(argv[0]);
    auto programName = argv0.baseName();
    QCoreApplication::setApplicationName(programName);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);

    QApplication app(argc, argv);

    QTranslator translator;
    if (translator.load(QLocale(), qAppName(), ".", KAS_INSTALL_TRANSLATIONDIR, ".qm"))
    {
        app.installTranslator(&translator);
    }

    GenCodeDialog dlg;
    dlg.show();
    return app.exec();
}