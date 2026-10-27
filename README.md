# CloudTrace AI

Cloud identity security and attack-path analysis platform.
Currently under construction..

## Local development

    env values
    docker compose up -d --build

- Frontend: http://localhost:3000
- Backend health: http://localhost:8000/api/v1/health
- API docs: http://localhost:8000/docs

## Common commands

    docker compose run --rm backend alembic upgrade head
    docker compose run --rm backend alembic revision --autogenerate -m "message"
    docker compose run --rm backend pytest
    docker compose run --rm frontend npm run lint
    docker compose run --rm frontend npm run typecheck
    docker compose logs -f backend
    docker compose down