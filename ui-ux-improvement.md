# certgot: строгий план улучшения UX/DX

## Цель

Сделать certgot самодиагностируемым операторским инструментом и удобным Go-проектом для развития:

```text
init -> doctor -> setup -> run -> status -> renew
```

Не менять уже достигнутые свойства без необходимости: атомарную публикацию cert/key, lock, проверку сертификатов, env-файлы, systemd hardening и ненулевые exit codes.

## Обязательные правила агента

1. Перед изменениями проверить `git status --short`; не перезаписывать чужие изменения.
2. Исправить синтаксическую ошибку workflow до функциональных изменений: проверить отступ `uses` в release job.
3. Не выполнять реальные production ACME-запросы в тестах.
4. Не менять существующий YAML-контракт без обратной совместимости и обновления README.
5. Каждый этап делать отдельным коммитом.
6. После каждого этапа запускать:

```bash
gofmt -w *.go
go test ./...
go test ./... -race -cover
go vet ./...
git diff --check
```

7. Если окружение не позволяет выполнить команду, записать это как блокер в итоговый отчет, не считать этап пройденным.

## Этап 0. Зафиксировать baseline

1. Записать текущую структуру проекта, git status и текущие команды сборки.
2. Запустить unit-тесты, race-тесты, vet и получить coverage.
3. Зафиксировать исходное покрытие и список известных команд:
   - `--config`;
   - `--setup`;
   - `--setup-interval`;
   - `--yes`;
   - `--version`.
4. Проверить `go build` для Linux и Darwin.
5. Создать отдельную ветку с префиксом `codex/`.

Критерий: baseline сохранен в PR/отчете; тесты проходят до начала UX/DX-изменений.

## Этап 1. Починить и укрепить CI

Файлы: `.github/workflows/build-release.yml`, `.github/systemd/*`.

1. Исправить YAML indentation release step у `uses: softprops/action-gh-release`.
2. Проверить workflow валидатором YAML.
3. Убедиться, что `quality` job запускается на `pull_request` и push основной ветки.
4. Оставить quality gates:
   - format;
   - `go test -race -cover`;
   - vet;
   - `go mod tidy` diff check;
   - `systemd-analyze verify`.
5. Разделить CI и release так, чтобы release зависел от quality и build.
6. Проверить, что `workflow_dispatch` действительно собирает артефакты.
7. Проверить, что release по tag не может быть создан при падении quality.

Критерий: workflow парсится; PR проверяется; release job запускается только после quality/build.

## Этап 2. Ввести доменную модель команд CLI

Файлы: `main.go`, новые `internal/cli/` или текущий пакет с постепенным выделением.

1. Сохранить обратную совместимость текущих flags.
2. Добавить команды:

```text
certgot run
certgot setup
certgot doctor
certgot status
certgot renew
certgot version
```

3. Старые вызовы трактовать как aliases:
   - без subcommand -> `run`;
   - `--setup` -> `setup`;
   - `--version` -> `version`.
4. Добавить единый parser command options.
5. Для каждой команды определить:
   - stdout contract;
   - stderr contract;
   - exit codes;
   - side effects;
   - можно ли запускать без root.
6. Не добавлять Cobra или другую CLI-библиотеку без необходимости; сначала использовать стандартный `flag` или небольшой собственный dispatcher.
7. Добавить `--help` с примерами команд и ссылкой на config.

Критерий: старые команды работают; новые команды имеют предсказуемый help и exit code; CLI-тесты не запускают реальные ACME/systemd операции.

## Этап 3. Реализовать `doctor`

Файлы: новый `doctor.go`, `doctor_test.go`, `main.go`, `readme.md`.

1. Реализовать:

```bash
certgot doctor --config ./config.yml
certgot doctor --config ./config.yml --output json
```

2. Проверять без выпуска сертификата:
   - существование и читаемость config;
   - неизвестные YAML-поля;
   - обязательные поля;
   - нормализованные домены и дубликаты;
   - допустимость provider;
   - наличие обязательных env/env_file;
   - права env-файлов;
   - доступность storage;
   - отсутствие небезопасных symlink-компонентов;
   - account key и registration;
   - существующие cert/key пары;
   - Telegram URL, если задан;
   - ACME directory connectivity;
   - systemd unit/timer, если выбран managed mode.
3. Внутренне представить результат как checks с полями:
   - `name`;
   - `status`: `ok`, `warning`, `error`;
   - `message`;
   - `domain` optional;
   - `remediation`.
4. Text output сделать коротким и actionable:

```text
✓ config valid
✓ cloudflare credentials found
! telegram disabled
✗ example.com env_file is not readable
  Fix: chmod 0600 /etc/certgot/secrets/example.com.env
```

5. JSON output сделать стабильным для automation.
6. Exit code `0` только если нет error; warning не ломает запуск.
7. Вынести проверки в независимые функции, чтобы их тестировать без внешней сети.

Критерий: оператор может понять готовность установки до ACME-запроса; каждая ошибка содержит исправление.

## Этап 4. Реализовать `status`

Файлы: новый `status.go`, `status_test.go`, `notify.go`/форматтеры при необходимости.

1. Добавить:

```bash
certgot status
certgot status --domain example.com
certgot status --output text
certgot status --output json
```

2. Не выполнять ACME-запросы.
3. Для каждого домена показывать:
   - domain;
   - status: `valid`, `renewal`, `missing`, `malformed`, `key-mismatch`, `not-yet-valid`, `error`;
   - expiry date;
   - days left;
   - provider;
   - release path.
4. Text output сделать табличным и пригодным для terminal.
5. JSON schema задокументировать в README.
6. Для `--domain` вернуть ошибку, если домен не найден в config.
7. Определить exit policy:
   - `0` — все valid;
   - `1` — missing/malformed/key-mismatch/error;
   - отдельный code для invalid CLI/config только если это оправдано.

Критерий: `status` заменяет ручной просмотр файлов и годится для cron/monitoring.

## Этап 5. Улучшить `renew`

Файлы: `main.go`, `app.go`, новый `renew.go`, тесты.

1. Добавить:

```bash
certgot renew --domain example.com
certgot renew --all
certgot renew --domain example.com --force
certgot renew --domain example.com --dry-run
```

2. Без `--force` использовать существующее renewal window.
3. `--force` требовать явный domain или `--all`; не разрешать случайный массовый ACME-запрос.
4. `--dry-run` не создавать ACME order и не менять storage.
5. Добавить `--staging` или config-поле для тестового ACME directory.
6. Добавить config-поле `renew_before` с default `720h`/30 дней.
7. Сохранять текущую обработку всех доменов при `run`, даже если один domain падает.
8. Отчет должен различать `valid`, `renewed`, `forced`, `failed`, `skipped`.

Критерий: оператор может безопасно проверить и точечно обновить сертификат без ручного редактирования config.

## Этап 6. Улучшить terminal UX

Файлы: `notify.go`, новый `output.go`, `main.go`, тесты.

1. Ввести единый renderer для run/doctor/status/renew.
2. Добавить flags:
   - `--output text|json`;
   - `--color auto|always|never`;
   - `--quiet`;
   - `--verbose`.
3. Цвет использовать только для TTY при `auto`.
4. Не смешивать JSON с логами в stdout: JSON только stdout, диагностические логи stderr.
5. Добавить итоговую сводку:

```text
3 certificates checked: 2 valid, 1 renewed, 0 failed
Report sent to Telegram
Completed in 8.4s
```

6. Добавить elapsed time для доменных операций в verbose mode.
7. Исключить секреты из всех text/json output.
8. Ошибки выводить с action/remediation, если она известна.

Критерий: интерактивный вывод читаем человеком; машинный вывод стабилен и не загрязнен логами.

## Этап 7. Реализовать `init`

Файлы: новый `init.go`, `init_test.go`, `config-example.yml`, `readme.md`.

1. Добавить:

```bash
certgot init --config ./config.yml
```

2. Интерактивно спросить:
   - ACME email;
   - domain;
   - provider;
   - env_file path;
   - certificate group/permissions;
   - Telegram optional.
3. Не спрашивать секреты в обычном terminal echo; предложить создать env-file с `0600`.
4. Не перезаписывать существующий config без `--force`.
5. Сгенерировать минимальный рабочий YAML только для одного domain.
6. После создания вывести следующие команды:

```text
Next:
  certgot doctor --config ./config.yml
  sudo certgot setup --config ./config.yml --setup-interval 2w --yes
```

7. Поддержать non-interactive flags для CI/automation.

Критерий: новый пользователь получает валидный минимальный config без чтения исходников.

## Этап 8. Добавить deploy/reload hooks

Файлы: `types.go`, `app.go`, новый `deploy.go`, тесты, README.

1. Выбрать безопасную модель конфигурации. Рекомендуемый вариант:

```yaml
certificates:
  - domain: example.com
    reload_units:
      - nginx.service
```

2. После успешной атомарной публикации выполнить reload только перечисленных systemd units.
3. Не запускать произвольную shell-строку из обычного YAML.
4. Для manual mode дать понятную ошибку, если systemd отсутствует.
5. Отдельно показывать `certificate renewed` и `reload succeeded/failed`.
6. Ошибка reload должна иметь четко определенную политику: либо fail run, либо warning. Зафиксировать выбор в README и config.
7. Добавить fake ServiceManager и тесты success/failure/unknown unit.

Критерий: после renewal сервисы, использующие сертификат, получают reload без ручных действий.

## Этап 9. Улучшить уведомления

Файлы: `notify.go`, `types.go`, тесты, README.

1. Сохранить Telegram URL для обратной совместимости.
2. Добавить режимы уведомлений:

```yaml
notifications:
  on: [renewed, error]
  telegram_url: ${TELEGRAM_URL}
```

3. Поддержать `on: [always]`, `on: [renewed, error]`, `on: [error]`, `on: []`.
4. Добавить hostname, version, duration и краткие remediation hints.
5. Разделить transport и message builder интерфейсами.
6. Тестировать HTTP через injected `RoundTripper` или client interface.
7. Добавить generic webhook только после стабилизации event model.

Критерий: уведомления не шумят при каждом valid run; ошибка содержит достаточно контекста для действия.

## Этап 10. Ввести structured logging

Файлы: `main.go`, `app.go`, новый `logging.go`, тесты, README.

1. Перейти на `log/slog`.
2. Добавить:

```bash
certgot run --log-format text
certgot run --log-format json
```

3. Поля событий:
   - `operation`;
   - `domain`;
   - `provider`;
   - `result`;
   - `duration_ms`;
   - `error`.
4. Секретные значения никогда не логировать.
5. Сохранить человекочитаемый text default для terminal/journald.
6. Для JSON логов использовать stderr, чтобы stdout оставался пригоден для `--output json`.

Критерий: journald/агрегатор может фильтровать события по domain/result/operation.

## Этап 11. Разделить код на модули и ввести interfaces

Файлы: текущие `certs.go`, `app.go`, `setup.go`, `notify.go`; новые `internal/*`.

1. Разделять по ответственности:

```text
cmd/certgot/
internal/cli/
internal/config/
internal/certificate/
internal/acme/
internal/storage/
internal/notify/
internal/systemd/
```

2. Не делать массовый rewrite. Переносить один boundary за коммит.
3. Ввести interfaces:
   - `CertificateIssuer`;
   - `CertificateStore`;
   - `Notifier`;
   - `ServiceManager`;
   - `Clock` при необходимости.
4. `runApp` сделать orchestration layer, не хранилищем и не renderer-ом.
5. Инжектировать dependencies в application service.
6. Оставить Lego/systemd реализации в adapters.
7. После каждого переноса сохранять внешнее поведение.

Критерий: workflow можно тестировать без ACME, systemd, Telegram и глобального окружения.

## Этап 12. Интеграционные тесты

Файлы: `integration/` или `testdata/`, CI workflow.

1. Добавить Pebble ACME test environment.
2. Добавить fake/mock DNS challenge provider или локальный DNS test server.
3. Проверить полный сценарий:

```text
config -> account -> order -> DNS-01 -> issue -> atomic publish -> status
```

4. Проверить renewal existing certificate.
5. Проверить interrupted publish и rollback.
6. Проверить lock contention.
7. Запускать integration job отдельно от быстрых unit-тестов.
8. Не включать production credentials.

Критерий: критический путь проверяется настоящим ACME test server, а не только helper-тестами.

## Этап 13. Developer workflow

Файлы: новый `justfile` или `Makefile`, README, CI.

1. Добавить команды:

```text
just check
just test
just race
just cover
just lint
just build
just integration
just systemd-verify
```

2. `just check` должен локально повторять quality gates CI.
3. Добавить `testdata/` для config, certs, env files и expected JSON.
4. Добавить golden tests для text/JSON output.
5. Документировать минимальную версию Go и Linux prerequisites.
6. Добавить pre-commit instructions без обязательных скрытых инструментов.

Критерий: contributor может выполнить один `just check` и получить тот же базовый сигнал, что CI.

## Этап 14. Versioning и release DX

Файлы: `main.go`, CI workflow, README.

1. Расширить `certgot version`:

```text
certgot v0.4.0
commit: abc1234
built: 2026-08-11T12:00:00Z
go: go1.24.2
```

2. Передавать version/commit/build time через ldflags.
3. Сохранить короткий однострочный режим для scripts: `--version --short`.
4. Ясно разделить Linux managed binaries и Darwin manual binaries.
5. Определить, нужен ли только Linux release, если setup — systemd-only.
6. В artifact включать binary, config example, README и checksum.
7. Рассмотреть provenance/signature после стабилизации pipeline.

Критерий: оператор точно знает, какую сборку запускает; contributor понимает release contract.

## Этап 15. Документация для happy path

Файлы: `readme.md`, `config-example.yml`.

1. В начало README добавить минимальный сценарий:

```bash
certgot init
certgot doctor
sudo certgot setup --setup-interval 2w --yes
certgot status
```

2. Документировать команды и flags через таблицу.
3. Документировать text/JSON output.
4. Добавить troubleshooting:
   - invalid credentials;
   - DNS propagation;
   - ACME rate limit;
   - lock held;
   - systemd failed;
   - permission denied;
   - Telegram failed.
5. Добавить backup/restore и migration instructions.
6. Добавить uninstall instructions, включая cleanup user/group только после подтверждения.
7. Описать provider-specific env через ссылку на Lego docs, не копировать полный каталог providers.

Критерий: оператор проходит setup, диагностику, renewal, recovery и uninstall без чтения исходников.

## Строгие критерии финальной приемки

Агент должен предоставить:

1. `go test ./...` — pass.
2. `go test ./... -race -cover` — pass; coverage не ниже baseline.
3. `go vet ./...` — pass.
4. `git diff --check` — pass.
5. CI workflow валиден.
6. `systemd-analyze verify` — pass на Linux runner.
7. CLI smoke tests:

```bash
certgot --version
certgot --help
certgot doctor --config testdata/config.yml
certgot status --config testdata/config.yml --output json
certgot renew --config testdata/config.yml --domain example.com --dry-run
```

8. Ни один smoke-test не делает production ACME-запрос.
9. Golden output стабилен.
10. В stdout JSON нет логов и credentials.
11. В документации есть копируемый happy path.
12. В итоговом отчете указаны:
    - что сделано;
    - что отложено;
    - измененные команды/контракты;
    - новые тесты;
    - coverage до/после;
    - известные ограничения.

Работа не считается завершенной, пока не работают как минимум `doctor`, `status`, `--output json`, безопасный `renew --dry-run`, единый `just check` и исправленный release workflow.
